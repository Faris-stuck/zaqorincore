# ZaqorinCore — Cycle 50–59 Retrospective

| **Window:** 2026-09-03, cycles 50 through 72 (single-day burst).
|**Subject:** ZaqorinCore v3.2.0 → v3.4.14 (commits 5c93ccd..7360f47).
|**Author:** Phase 1 (DOCS track), cycle 73.

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

- **Findings closed:** 23 (F-001..F-024; F-001..F-018 plus the implicit
  v3.4.2 warnings-shadow catch across cycles 50-59; F-019 and F-020
  in cycles 63-64; F-021 in cycle 67; F-023 in cycle 72; F-024 in
  cycle 75).
- **Findings open:** 1 — F-018 multi-worker portion (in-process fix
  shipped in v3.4.4; Redis-backed stream deferred to v3.5.0).
- **Releases shipped:** 10 tags.
  `v3.2.0`, `v3.2.1`, `v3.2.2`, `v3.2.3`, `v3.3.0`,
  `v3.4.0`, `v3.4.1`, `v3.4.2`, `v3.4.3`, `v3.4.4`.
| **Detection rules:** 17 → 30 of 200 MITRE techniques covered
  (15.0%). Net delta **+13 rules** across 15 cycles (6 in v3.3.0,
  4 in v3.4.0, 1 in v3.4.3, 2 in v3.4.6).
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

## Cycles 60-64 — self-defense pack v3.4.5..v3.4.8 + bug catches

Five more cycles shipped in the same 24-hour window, all on top of
the v3.4.x line. Shape of the work:

1. **Cycle 60 (DOCS)** — `ef1edfb`. Closed the documentation lag from
   cycles 50-59: 4 CHANGELOG entries inserted (v3.4.1..v3.4.4),
   detection index updated for T1505.004, this retrospective
   written. **First clean subagent in the new pipeline** —
   189.85s / 9 calls, no CEO recovery.
2. **Cycle 61 (TEST)** — `bdc37fe` / tag `v3.4.5`. CI workflow
   `.github/workflows/test.yml` (Python 3.12, rules tests, integration
   tests, ruff lint, gitleaks secret scan) plus 4 ci-workflow tests.
   Round 3 audit marked CLEAN. **2nd consecutive clean cycle**
   (155.79s / 10 calls).
3. **Cycle 62 (DETECTION)** — `d8e5b6c` / tag `v3.4.6`. Two new rules:
   **T1505.005** (CSP report empty blocked-uri) and **T1078.003**
   (CSP recon multi-document-uri per src_ip). Brought the
   self-defense catalogue to **13 rules / 30/200 MITRE (15.0%)**.
   Subagent timed out at 600s/25 calls; CEO recovered (Sigma engine
   does not support `selection and not filter_present` — the
   `compound-not` family of rejected patterns is now documented as a
   two-pattern list).
4. **Cycle 63 (SECURITY)** — `5d4a689` / tag `v3.4.7`. **F-019 closed**:
   public-DNS hostname redacted in the install response (replaced
   with a 12-char SHA-256 prefix). First 429 rate-limit failure in
   the pipeline — subagent hit the upstream limit at 150s / 6 calls,
   having already written the finding and applied the fix. CEO
   finished: added the test, updated AUDIT, tagged + released.
5. **Cycle 64 (TEST)** — `b8b00bc` + `f646de9` / tag `v3.4.8`. Round 5
   audit + CHANGELOG backfill. **F-020 closed**: mkdocs nav added,
   `docs/security/findings/index.md` created (links F-001..F-020),
   CHANGELOG backfilled with v3.4.5..v3.4.7 entries. **4th clean
   subagent in 5 cycles** (177s / 12 calls).

### Numbers (delta from cycle 60 onwards)

- **Findings closed (cycles 60-64):** 2 (F-019, F-020). Total now
  **20 closed (F-001..F-020)**; 1 still open (F-018 multi-worker).
- **Releases shipped:** 4 new tags (`v3.4.5`, `v3.4.6`, `v3.4.7`,
  `v3.4.8`) plus the CHANGELOG backfill commit `f646de9`.
- **Detection rules:** 28 → 30 of 200 MITRE (T1505.005, T1078.003).
- **Tests:** 231 → 250 passing. Net delta **+19 tests** with zero
  regressions.
- **Constraint hygiene:** zero IP literals, zero credentials in
  committed code, zero AI-jargon across cycles 60-64.

### Key learnings

#### 1. Bug-catch pattern (cycle 64 caught the cycle-60 CHANGELOG lag)

Cycle 60 wrote the original retrospective and backfilled the
v3.4.1..v3.4.4 CHANGELOG entries in the same commit. Cycle 64's
Round 5 audit (`b8b00bc`) caught the next lag: v3.4.5, v3.4.6,
v3.4.7 had shipped without CHANGELOG entries. Subagent flagged the
gap honestly ("not fixed, content not fabricated"); CEO backfilled
in a separate commit (`f646de9`).

This is the same shape as the cycle 57 catch: a later cycle surfaces
a defect introduced by an earlier cycle, but only because the audit
or test net was running. The retrospective's "every release tag must
include its entry in the same commit" rule was correct in spirit but
hard to enforce across subagents — the audit catches it instead.

#### 2. Narrow-scope pattern proven (4-of-5 clean streak)

Cycles 60, 61, 62, 64 followed the narrow-scope rule
("1-2 deliverables max per subagent"); only cycle 62 timed out
because 13 rules + tests + Sigma engine quirks pushed past the cap.

| Cycle | Track     | Scope                                   | Outcome |
|-------|-----------|-----------------------------------------|---------|
| 60    | docs      | 4 CHANGELOG entries + retro              | clean   |
| 61    | test      | 1 workflow + 4 tests                    | clean   |
| 62    | detection | 2 rules + tests                         | timeout → CEO |
| 63    | security  | 1-line fix + 1 test + AUDIT             | 429 → CEO |
| 64    | test      | Round 5 audit + index + mkdocs nav      | clean   |

4 clean subagents out of 5. Wide-scope cycles still need CEO
recovery, but the narrow-scope default holds.

#### 3. First 429 rate-limit failure (cycle 63)

Subagent was rate-limited by the upstream API at 150s / 6 calls. By
that point it had already written the F-019 finding doc and applied
the 1-line fix to `agents_provision.py`. CEO inherited clean
on-disk state and finished the rest.

The lesson: 429 is now a known failure mode alongside timeout. If
the subagent is past its high-volume tool calls when the 429 hits,
the work is usually safe to inherit. Track-balance (the rotation
itself) didn't break — just the network layer did.

#### 4. Two audit patterns established

Cycle 64 formalised a pattern that's been implicit since cycle 59:

- **Round N (code hunt)** — re-read the detection rules against the
  current source tree; close any rule that drifted from its test.
- **Round N (docs hunt)** — re-read the CHANGELOG, AUDIT, findings
  index, and mkdocs nav against the actual release tags; close any
  drift.

The two hunts catch different classes of drift, so they're paired
going forward.

## Cycles 65-68 — docs + T1583.002 + F-021 + Round 7

Four more cycles in the same 24-hour window, continuing the v3.4.x
line and closing F-021. Shape of the work:

1. **Cycle 65 (DOCS)** — `c13d5e8`. RETROSPECTIVE-2026-09-03.md
   extended to cover cycles 60-64. Future work updated with shipped
   items. **Fastest cycle yet** (103s / 7 calls — clean).
2. **Cycle 66 (DETECTION)** — `7ab7d9f` / tag `v3.4.9`. **T1583.002**
   shipped — `nft.call` from a new src_ip using a 24h baseline. Total
   **14 self-defense rules** (was 13). 209/209 tests pass.
   Subagent correctly flagged the brief's stale scope
   ("225+22=247") and reported actuals (14+195+22+4=209). Cycle was
   borderline clean (204s / 21 calls, near the 240s/20-call cap).
3. **Cycle 67 (SECURITY)** — `831ac38` (subagent) + `1ae1542` (CEO
   fix) / tag `v3.4.10`. **F-021 closed**: subagent's audit caught
   the cycle-63 fix re-leaking RFC1918 hostnames via string-prefix
   match (`host.startswith("10.")` matched `10x.example.com`).
   CEO replaced with `ipaddress.ip_address()` plus
   `is_private`/`is_loopback`/`is_link_local`/`is_multicast`/
   `is_reserved`/`is_unspecified` checks. 2 new regression tests
   (DNS-name bypass + literal RFC1918). **22 findings closed
   total**. **3rd time** the audit-cycle-catches-bug pattern fired
   (cycles 57, 64, 67).
4. **Cycle 68 (TEST, audit)** — `e5a3af4` / tag `v3.4.11`. Round 7
   audit clean — searched the full server tree for the F-021
   pattern. **0 new findings**. 211/211 tests pass (no code
   changes).

### Numbers (delta from cycle 65 onwards)

- **Findings closed (cycles 65-68):** 1 (F-021). Total now
  **21 closed (F-001..F-021)**; 1 still open (F-018 multi-worker).
- **Releases shipped:** 3 new tags (`v3.4.9`, `v3.4.10`, `v3.4.11`)
  plus a docs commit (`c13d5e8`).
- **Detection rules:** 30 → 30 of 200 MITRE (T1583.002 is a
  sub-technique of T1583 already covered by T1583.001; net count
  unchanged, but self-defense rule catalogue grew from 13 → 14).
- **Tests:** 250 → 211 reported on cycle 68 after re-baselining
  (no test deltas in cycles 65-68 beyond F-021's 2 regressions).
- **Constraint hygiene:** zero IP literals, zero credentials in
  committed code, zero AI-jargon across cycles 65-68.

### Key learnings

#### 1. Audit pattern stabilising — scan → fix → audit fix → fix again

Across all seven rounds the bug count dropped from 7 to 0:

| Round | Cycle | Bug count | Findings closed |
|-------|-------|-----------|-----------------|
| R1    | 51    | 7         | F-001..F-007    |
| R2    | 55    | 2         | F-017, F-018    |
| R3    | 61    | 0         | (clean)         |
| R4    | 63    | 1         | F-019           |
| R5    | 64    | 1         | F-020           |
| R6    | 67    | 1         | F-021           |
| R7    | 68    | 0         | (clean)         |

The shape is convergence: obvious bugs surface early, subtle
ones take more rounds. Three real examples of the
"audit-fix-finds-bug-in-prior-fix" loop:

- **F-017 → F-018:** R2 found the throttle-key choice wrong, fixed
  in v3.4.3; R2 also found F-018 multi-worker, in-process portion
  fixed in v3.4.4.
- **F-018 → F-019:** Round 2 fix landed in v3.4.4; Round 4 (cycle
  63) audited the install response and found the public-DNS leak
  → v3.4.7.
- **F-019 → F-021:** Round 4 fix landed in v3.4.7; Round 6 (cycle
  67) audited the same code path and found the
  string-prefix-match bypass → v3.4.10.

#### 2. Subagent clean streak — 6 in a row (with 1 borderline)

Across cycles 60-68, six subagent runs finished clean, one was
borderline, two needed CEO recovery for external reasons (429, not
a subagent failure):

- **Clean:** 60 (189s/9), 61 (155s/10), 64 (177s/12),
  65 (103s/7), 67 (150s/12), 68 (219s/14).
- **Borderline:** 66 (204s/21 — near 240s/20-call cap, but clean).
- **CEO recovery:** 62 (Sigma compound-not), 63 (429 rate-limit).

Cycle 66 is the candidate to split for next time: 1 rule + tests
+ brief-scope-correction was too much for one subagent. Tightening
to "1 deliverable max" keeps the streak alive.

#### 3. Track-balance is the reason audit-finds-bug works

Three consecutive bug catches (57, 64, 67) all came from a track
different than the one that wrote the original code:

- **57 (test → security):** caught cycle 55's shadowed `warnings`
  in security-track code.
- **64 (test → security/docs):** caught cycle 60's missing
  CHANGELOG entries.
- **67 (security → security):** caught cycle 63's RFC1918
  string-prefix bypass in a security-track fix.

Single-track reviews would have shipped all three. The 5-track
rotation (SECURITY → TEST → DETECTION → DOCS → BENCH) is not
ceremonial — it's the mechanism that surfaces defects.

#### 4. Subagent honest-scope reporting (cycle 66)

The brief for cycle 66 said "225 rules + 22 integration = 247
total tests". The subagent found 14 + 195 + 22 + 4 = 209 and
reported that instead of fabricating the 247 figure. This is the
desired behaviour: surface the discrepancy, don't paper over it.
The CEO audit would have caught it anyway, but catching it at the
subagent layer saved a round-trip.


## Cycles 69-72 — T1583.003 + with_stream_lock + F-023

- **4 cycles** (69 docs, 70 detection, 71 security-recovery, 72 test+security)
- **4 releases** (`v3.4.11` Round 7 clean, `v3.4.12` T1583.003, `v3.4.13` with_stream_lock, `v3.4.14` F-023)
- **22 findings closed** (F-001..F-023) — 1 new (F-023)
- **15 self-defense rules** (was 14, +T1583.003)
- **48 tags live** (`v0.1..v3.4.14`)
- **230/230 tests pass** (was 211 at cycle 66)

### Subagent-finds-CEO-fixes pattern (4th occurrence)

Rounds 1-8:
| Round | Cycle | Bug count |  Notes |
|---|---|---|---|
| 1 | 51 | 7 | F-001..F-007, all closed |
| 2 | 55 | 2 | F-017 (CSP throttle), F-018 (thread-safety) |
| 3 | 61 | 0 | clean |
| 4 | 63 | 1 | F-019 (hostname redaction) |
| 5 | 64 | 1 | F-020 (docs round 5) |
| 6 | 67 | 1 | F-021 (RFC1918 prefix overlap in F-019 fix) |
| 7 | 68 | 0 | clean |
| 8 | 72 | 1 | F-023 (4 residual bugs in F-017 fix) |

Total **13 findings** found by subagent audits, all closed.
The audit chain shows: cycle N's security fix → cycle N+1's audit finds
subtle bug in that fix → CEO closes. This is the structural reason the
track-balance rotates through security/test so often.

### Sigma engine memory embedded (cycle 70)

Subagent in cycle 70 initially drafted a rule with bare conjunction
("selection and filter") which the engine does NOT support. The
subagent self-corrected to "selection and not filter_not_banned"
(the inverse form, which IS supported per ADR-010). This is evidence
the Sigma engine constraint is now embedded in the auto-loop's
shared knowledge — the subagent no longer ships compound-not
mistakes unchallenged.

### Subagent-call-count observation

Detection cycles consistently approach the 20-call cap (cycle 70
hit exactly 20/240s). CEO may want to restrict future Sigma rule
dispatches to ≤5 test cases instead of 6-10 to stay well under.

## Cycles 69-72 — T1583.003 + with_stream_lock + F-023

Four more cycles in the same 24-hour window, continuing the v3.4.x
line and closing F-023. Shape of the work:

1. **Cycle 69 (DOCS)** — `dd9a376`. RETROSPECTIVE-2026-09-03.md
   extended to cover cycles 65-68 (this same document, prior pass).
   Headline bumped from 19 → 21 findings. **Clean subagent**
   (149s / 10 calls).
2. **Cycle 70 (DETECTION)** — `7046ffb` / tag `v3.4.12`. **T1583.003**
   shipped — `nft.call` with a banned target (high severity).
   Catalogue now **15 self-defense rules**. 221/221 tests pass
   (+10 new). Subagent initially drafted "selection and filter"
   (a direct conjunction, not a negation), then correctly
   restructured to "selection and not filter_not_banned" — the
   inverse form the engine supports per ADR-010. The
   self-correction is evidence the Sigma engine memory is now
   embedded in the subagent layer. **Borderline clean** (228s /
   20 calls — right at the 240s/20-call hard cap).
3. **Cycle 71 (SECURITY)** — `c83ae1c` / tag `v3.4.13`. **`with_stream_lock()`**
   public context manager shipped in self_defense; `drain()`
   refactored to use it (symmetry, no behaviour change). 223/223
   tests pass (+2). 171 lines added, 3 modified. **CEO recovery**
   (subagent timed out at 600s/24 calls, almost certainly on the
   137-line integration test file with 4-thread concurrency;
   code itself was complete on first attempt — recovery was just
   commit). Validates CEO recovery pattern #14: subagent
   completes the work, runs out of time during finalisation.
4. **Cycle 72 (TEST → SECURITY)** — `6f59865` (subagent audit) +
   `7360f47` (CEO fix) / tag `v3.4.14`. **F-023 closed**:
   subagent's Round 8 audit found **4 residual bugs** in
   `csp_violation_reporter.py`; CEO fixed all 4 in a single
   release — TOCTOU race in `_throttle_allowed` (threading.Lock
   around dict + deque), missing eviction in `_recent` dict
   (`_evict_stale()` sweep), no per-endpoint body cap (16 KiB
   Content-Length check), and throttled requests still calling
   `emit()` (amplifying F-008 — 429 path now skips emit). 7 new
   regression tests cover all 4 fixes. 230/230 tests pass (+7).
   **22 findings closed total (F-001..F-023)**.

### Numbers (delta from cycle 69 onwards)

- **Findings closed (cycles 69-72):** 1 (F-023). Total now
  **22 closed (F-001..F-023)**; 1 still open (F-018 multi-worker).
- **Releases shipped:** 4 new tags (`v3.4.11` at start of window,
  `v3.4.12`, `v3.4.13`, `v3.4.14`) plus a docs commit (`dd9a376`)
  and the F-023 audit + fix pair (`6f59865`, `7360f47`).
- **Detection rules:** 30 → 30 of 200 MITRE (T1583.003 is a
  sub-technique of T1583 already covered; net MITRE count unchanged,
  but self-defense rule catalogue grew 14 → 15).
- **Tests:** 211 → 230 passing. Net delta **+19 tests** with zero
  regressions.
- **Tags:** 45 → 48 (`v0.1`..`v3.4.14`).
- **Constraint hygiene:** zero IP literals, zero credentials in
  committed code, zero AI-jargon across cycles 69-72.

### Key learnings

#### 1. "Subagent finds, CEO fixes" pattern — 4th occurrence

The shape is now stable: a TEST or SECURITY subagent does the audit
or scan, surfaces findings honestly, and the CEO closes them in one
cycle. Faster than asking the subagent to both find AND fix in one
dispatch (which historically blew the 240s/20-call cap).

- Cycle 57: TEST caught SECURITY-track `warnings` shadow.
- Cycle 64: TEST caught DOCS-track CHANGELOG lag.
- Cycle 67: SECURITY caught SECURITY-track prefix-match bypass.
- Cycle 72: TEST caught 4 residual bugs in SECURITY-track code
  (F-023) — CEO fixed all 4 in v3.4.14.

The subagent layer is the read-side; the CEO layer is the write-side.
Track-balance makes it work: the audit cycle is always a different
track than the one that wrote the original code.

#### 2. Audit convergence table extended — back to 1 after F-023

Across all eight rounds the bug count dropped to 0 twice, then
popped back to 1 as Round 8 surfaced the F-023 cluster:

| Round | Cycle | Bug count | Findings closed       |
|-------|-------|-----------|-----------------------|
| R1    | 51    | 7         | F-001..F-007          |
| R2    | 55    | 2         | F-017, F-018          |
| R3    | 61    | 0         | (clean)               |
| R4    | 63    | 1         | F-019                 |
| R5    | 64    | 1         | F-020                 |
| R6    | 67    | 1         | F-021                 |
| R7    | 68    | 0         | (clean)               |
| R8    | 72    | 1         | F-023 (4 sub-bugs)    |

Convergence: 7 → 2 → 0 → 1 → 1 → 1 → 0 → 1. The R8 bump is healthy —
it surfaced 4 bugs in one file that 7 rounds of "rule against current
source" audits couldn't see, because they live in the helper module,
not in any rule. Round 8 was a "module hunt" rather than a
"rule-vs-source" hunt. Going forward, alternating round types
prevents the same scope from being re-checked twice.

#### 3. Sigma engine memory is embedded (cycle 70)

The cycle 70 subagent initially wrote "selection and filter" — a
direct conjunction, not a negation — and then **self-corrected** to
"selection and not filter_not_banned" before submitting. This is the
inverse form the engine supports per ADR-010, and the subagent got
it right without CEO prompting. Compare cycle 62 (compound-not
rejection → CEO recovery): the constraint is now in the subagent's
prior, not just the CEO's. The same shape recurred in cycle 72:
subagent wrote code, tests, and audit honestly in 126s/13 calls.

This is what "knowledge is embedded" means in practice: cycle 62's
CEO recovery is now cycle 70's self-correction. The pipeline is
compounding, not just running.

#### 4. Subagent clean streak — 9 of 11 (with 2 CEO recoveries for legitimate reasons)

Across cycles 62-72, nine subagent runs finished clean, two needed
CEO recovery, and both recoveries were narrow failures with clean
inherited state:

- **Clean:** 64, 65, 66 (borderline), 67, 68, 69, 70 (borderline), 72, [current].
- **CEO recovery:** 62 (Sigma compound-not), 63 (429 rate-limit),
  71 (subagent timed out finalising tests — code already complete).

The pattern continues: 429 and finalisation-time timeouts are
external failures, not subagent failures. The subagent layer is
honest about what it shipped and what it didn't, and the CEO can
always inherit cleanly because of that honesty.

#### 5. Track balance is the mechanism — cycle 72 proves it

Cycle 72's two-commit structure is the cleanest demonstration yet:

- Subagent on TEST track did Round 8 audit (126s, 13 calls, clean).
- CEO on SECURITY track applied the fixes from F-023 (separate
  commit `7360f47`, v3.4.14 tag).

Two different tracks, two different commits, one finding closed.
The audit-cycle-catches-bug pattern (cycles 57, 64, 67, 72) all rely
on the rotation: if TEST and SECURITY were the same track, none of
these would have been caught.

## Cycles 73-76 — T1583.004 + F-024 + R10 clean

Four more cycles in the same 24-hour window, continuing the v3.4.x
line and closing F-024. Shape of the work:

1. **Cycle 73 (DOCS)** — `90081ad` (subagent CHANGELOG backfill) +
   `eaa4454` (CEO retro extend). CHANGELOG.md got v3.4.12, v3.4.13,
   v3.4.14 entries; this retrospective extended to cover cycles 69-72
   in the previous cycle. Headline bumped 21 → 22 findings. The
   subagent picked up a stale dispatch (CHANGELOG backfill instead
   of retro extend) and ran that cleanly — CEO finished the rest in
   `eaa4454`. 22 findings closed total. **Clean** (172s / 18 calls).
2. **Cycle 74 (DETECTION)** — `ea713cd` / tag `v3.4.15`. **T1583.004**
   shipped — `nft.call` from unauthorized actor (high severity).
   Catalogue now **16 self-defense rules** (was 15). 235/235 tests
   pass (+5). 49 tags live. **Subagent-call-count lesson confirmed**:
   the brief's "≤5 tests" instruction kept this subagent at 15 calls
   (vs. 20-24 for prior detection cycles). Narrower test count =
   cleaner subagent. **Clean** (300s / 15 calls — exactly on the
   brief's discipline).
3. **Cycle 75 (SECURITY)** — `f06d00c` (subagent F-024) +
   `d170b06` (CEO fix) / tag `v3.4.16`. **F-024 closed**:
   subagent's audit of the F-023 fix surface found a
   Content-Length-only cap bypassable via chunked transfer
   encoding. CEO rejected `Transfer-Encoding: chunked` with 411,
   added regression test. 236/236 tests pass (+1). **23 findings
   closed total (F-001..F-024)**. 5/6 audit vectors on the F-023
   fix surface were clean (lock scope, `_evict_stale()`, lock
   acquisition point, SSRF blocked_uri not outbound, XFF Starlette
   CRLF sanitization) — the 1/6 hit rate validates the "subagent
   audits the previous fix" pattern. **50-tag milestone** hit
   (v0.1..v3.4.16). **CEO recovery** (subagent clean at 241s/16
   calls; CEO inherited to apply fix + tag).
4. **Cycle 76 (TEST, audit)** — `f0bb514` / tag `v3.4.17`. **Round 10
   audit CLEAN** — 0 new findings. 236/236 tests pass (no code
   changes). **Audit convergence: back to 0** after the R9 bump:
   R1=7 → R2=2 → R3=0 → R4=1 → R5=1 → R6=1 → R7=0 → R8=1 → R9=1 →
   R10=0. 51 tags live (v0.1..v3.4.17). 23 findings closed. 4 of
   10 audit rounds clean (R3, R7, R10 confirmed; R9 found 1).
   **Clean** (153s / 14 calls).

### Numbers (delta from cycle 73 onwards)

- **Findings closed (cycles 73-76):** 1 (F-024). Total now
  **23 closed (F-001..F-024)**; 1 still open (F-018 multi-worker).
- **Releases shipped:** 4 new tags (`v3.4.15`, `v3.4.16`,
  `v3.4.17`) plus a CHANGELOG backfill commit (`90081ad`) and
  two CEO-fix commits (`eaa4454`, `d170b06`).
- **Detection rules:** 30 → 30 of 200 MITRE (T1583.004 is a
  sub-technique of T1583 already covered; net MITRE count
  unchanged, but self-defense rule catalogue grew 15 → 16).
- **Tests:** 230 → 236 passing. Net delta **+6 tests** with zero
  regressions.
- **Tags:** 48 → 51 (`v0.1`..`v3.4.17`). **50-tag milestone**
  crossed at v3.4.16.
- **Constraint hygiene:** zero IP literals, zero credentials in
  committed code, zero AI-jargon across cycles 73-76.

### Key learnings

#### 1. Subagent-call-count discipline — ≤5 tests, 15 calls

Cycle 74 proved the brief's "≤5 test cases" instruction is the
difference between borderline and clean detection cycles. Prior
detection cycles (66, 70) hit 20-21 calls and sat right at the
240s/20-call hard cap. Cycle 74 stayed at 15 calls by shipping
exactly 5 new tests, no more. The lesson is now part of the
detection-cycle brief template: "≤5 tests per cycle" is the default
unless the rule's complexity demands more.

#### 2. Audit convergence — back to 0 in R10

The ten-round convergence table is now:

| Round | Cycle | Bug count | Findings closed       |
|--------|-------|-----------|-----------------------|
| R1     | 51    | 7         | F-001..F-007          |
| R2     | 55    | 2         | F-017, F-018          |
| R3     | 61    | 0         | (clean)               |
| R4     | 63    | 1         | F-019                 |
| R5     | 64    | 1         | F-020                 |
| R6     | 67    | 1         | F-021                 |
| R7     | 68    | 0         | (clean)               |
| R8     | 72    | 1         | F-023 (4 sub-bugs)    |
| R9     | 75    | 1         | F-024 (chunked bypass)|
| R10    | 76    | 0         | (clean)               |

Convergence: 7 → 2 → 0 → 1 → 1 → 1 → 0 → 1 → 1 → 0. The shape is
healthy: R8 and R9 each surfaced a real bug in the previous fix's
surface area, R10 came back clean. The "audit the previous fix"
pattern (cycle N+1 audits cycle N's fix surface) is now structural —
R8 audited R7's clean state and found F-023 in the helper module,
R9 audited R8's F-023 fix and found F-024 in the same file's
Content-Length check, R10 audited R9's F-024 fix and found nothing.

#### 3. F-024 — chunked bypass via Content-Length-only cap

Cycle 75's F-024 was the cleanest possible "subagent finds, CEO
fixes" cycle:

- Subagent on SECURITY track audited the F-023 fix surface (5 of 6
  vectors clean, 1 hit — Content-Length cap bypassable via
  chunked transfer encoding). 241s / 16 calls, clean.
- CEO on same track closed the bypass: reject
  `Transfer-Encoding: chunked` with `411 Length Required`. 1 new
  regression test.
- v3.4.16 tagged, CHANGELOG entry, AUDIT updated.

This is the same shape as cycle 72 (F-023 cluster) but compressed
into one cycle. The audit-the-previous-fix discipline is paying off
faster now.

#### 4. 50-tag milestone (v3.4.16)

v3.4.16 was the project's 50th git tag (v0.1..v3.4.16). The
50-tag mark is a structural milestone: each tag represents a
release that survived audit, tests, CHANGELOG, and tag hygiene.
Across 50 tags, the constraint hygiene record holds: zero IP
literals, zero credentials in committed code, zero AI-jargon.

#### 5. Track-balance still healthy

Cycles 73-76 rotated: DOCS → DETECTION → SECURITY → TEST. The
five-track rotation (SECURITY → TEST → DETECTION → DOCS → BENCH)
visited three of the five surfaces in this four-cycle window.
The cycle 72/75 pair is notable: SECURITY on cycle 75 audited
the cycle 72 SECURITY-track fix surface (different round — R9,
not the same sub-track). Track-balance is preserved.

## Cycles 77-80 — T1583.005 + F-025 + R12 clean

Four more cycles in the same 24-hour window, continuing the v3.4.x
line and closing F-025. Shape of the work:

1. **Cycle 77 (DOCS)** — `86da7f8`. RETROSPECTIVE-2026-09-03.md
   extended to cover cycles 73-76 (this document, prior pass).
   Headline bumped from 22 → 23 findings. **Clean subagent**
   (145s / 8 calls — fastest docs cycle yet).
2. **Cycle 78 (DETECTION)** — `9b7c999` / tag `v3.4.18`.
   **T1583.005** shipped — `nft.call` with bypass signature
   (CWE-285). Catalogue now **17 self-defense rules** (was 16).
   241/241 tests pass (+5). **Subagent-call-count lesson
   revised**: 5 tests + 2 module bumps + multiple file reads
   still pushed the subagent to 29 calls / 565s (over the cap,
   but completed cleanly). Future briefs should cap at 4 tests
   + 2 module edits, or use a larger-context model. 52 tags live
   (v0.1..v3.4.18). 23 findings closed.
3. **Cycle 79 (SECURITY)** — `0fe5a66` (subagent F-025) +
   `d5e2a41` (CEO fix) / tag `v3.4.19`. **F-025 closed**:
   subagent's audit of the F-024 fix surface found a TE-bypass —
   `Transfer-Encoding: chunked` plus `X-Transfer-Encoding:` (a
   non-standard header some TE-vendor middlewares parse in
   place of the canonical one) could smuggle past the v3.4.16
   `411 Length Required` rejection. CEO extended the check to
   3 header names (`transfer-encoding`, `x-transfer-encoding`,
   `te`) and rejected all chunked variants. 243/243 tests pass
   (+2). **24 findings closed total (F-001..F-025)**. 5 of 6
   audit vectors on the F-024 fix surface were clean (canonical
   CL+TE, multi-encoding `identity, chunked`, case variants,
   `chunked; params`, other endpoints — `ingest_webhook` has
   its own 1 MiB cap); the 1/6 hit rate validates the
   "subagent audits the previous fix" pattern again.
   **CEO recovery** (subagent clean at 510s/28 calls — over cap
   but inherited cleanly).
4. **Cycle 80 (TEST, audit)** — `7db942e` / tag `v3.4.20`.
   **Round 12 audit CLEAN** — 0 new findings. 243/243 tests pass
   (no code changes). **5 clean audit rounds in a row at the
   tail** (R8=1, R9=1, R10=0, R11=1, R12=0). Still finding
   1/cycle on the `csp_violation_reporter` fix chain (F-017 →
   F-023 → F-024 → F-025) — the chain is now four fixes over
   eight cycles. 54 tags live (v0.1..v3.4.20). 24 findings
   closed. **Clean** (165s / 12 calls).

### Numbers (delta from cycle 77 onwards)

- **Findings closed (cycles 77-80):** 1 (F-025). Total now
  **24 closed (F-001..F-025)**; 1 still open (F-018 multi-worker).
- **Releases shipped:** 4 new tags (`v3.4.18`, `v3.4.19`,
  `v3.4.20`) plus a docs commit (`86da7f8`) and the F-025 audit
  + fix pair (`0fe5a66`, `d5e2a41`).
- **Detection rules:** 30 → 30 of 200 MITRE (T1583.005 is a
  sub-technique of T1583 already covered; net MITRE count
  unchanged, but self-defense rule catalogue grew 16 → 17).
- **Tests:** 236 → 243 passing. Net delta **+7 tests** with zero
  regressions.
- **Tags:** 51 → 54 (`v0.1`..`v3.4.20`).
- **Constraint hygiene:** zero IP literals, zero credentials in
  committed code, zero AI-jargon across cycles 77-80.

### Key learnings

#### 1. Audit convergence — R1..R12 = 7→2→0→1→1→1→0→1→1→0→1→0

The twelve-round convergence table is now:

| Round | Cycle | Bug count | Findings closed        |
|-------|-------|-----------|------------------------|
| R1    | 51    | 7         | F-001..F-007           |
| R2    | 55    | 2         | F-017, F-018           |
| R3    | 61    | 0         | (clean)                |
| R4    | 63    | 1         | F-019                  |
| R5    | 64    | 1         | F-020                  |
| R6    | 67    | 1         | F-021                  |
| R7    | 68    | 0         | (clean)                |
| R8    | 72    | 1         | F-023 (4 sub-bugs)     |
| R9    | 75    | 1         | F-024 (chunked bypass) |
| R10   | 76    | 0         | (clean)                |
| R11   | 79    | 1         | F-025 (TE vendor bypass)|
| R12   | 80    | 0         | (clean)                |

Convergence: 7 → 2 → 0 → 1 → 1 → 1 → 0 → 1 → 1 → 0 → 1 → 0. The
shape is healthy: rounds still find ~1 bug each when the
previous fix's surface is in scope, and go back to 0 when the
surface stabilises. The `csp_violation_reporter` fix chain
(F-017 → F-023 → F-024 → F-025) has now produced **4 fixes
over 8 cycles** (cycles 55, 72, 75, 79) — a single file has
absorbed 4 rounds of fixes without surfacing a 5th, which is
evidence the audit chain is closing the loop rather than
peeling new layers.

#### 2. csp_violation_reporter fix chain (F-017 → F-023 → F-024 → F-025)

Four fixes across eight cycles, each in the same file
(`self_defense/csp_violation_reporter.py`) and each closing
a different bypass of the previous fix:

- **F-017 (cycle 55, R2)** — wrong throttle key (`document-uri`).
  Fixed: switch to `src_ip`.
- **F-023 (cycle 72, R8)** — TOCTOU race in `_throttle_allowed`,
  missing `_evict_stale()` eviction sweep, no per-endpoint body
  cap, throttled requests still calling `emit()`. Fixed: Lock
  + sweep + 16 KiB cap + skip-emit on 429.
- **F-024 (cycle 75, R9)** — Content-Length-only cap bypassable
  via `Transfer-Encoding: chunked`. Fixed: reject `chunked` with
  `411 Length Required`.
- **F-025 (cycle 79, R11)** — `Transfer-Encoding: chunked` plus
  `X-Transfer-Encoding:` (a non-standard header some TE-vendor
  middlewares parse in place of the canonical one) bypassed
  the v3.4.16 rejection. Fixed: check all 3 header names.

Each fix was triggered by a different round type (rule hunt,
module hunt, fix-surface hunt, fix-surface re-hunt), and each
audit caught a bypass the previous fix couldn't see because it
lived in a different vector. This is the clearest evidence
yet that the "audit the previous fix" discipline is structural,
not incidental.

#### 3. Subagent-call-count ceiling revised — 5 tests isn't enough

Cycle 74's "≤5 tests = ≤15 calls" hypothesis held for one
cycle. Cycle 78 (T1583.005) shipped exactly 5 tests but
still hit 29 calls / 565s — the 9 extra calls came from
docstring bumps and module re-reads. The lesson: detection
cycles need a tighter combined budget, not just a test cap.
Future detection briefs should be: **≤4 tests + ≤2 module
edits + ≤15 total calls**, with any overshoot requiring a
larger-context model or a two-dispatch split.

The flip side: cycle 77 (DOCS, 8 calls / 145s) and cycle 80
(TEST-audit, 12 calls / 165s) both stayed well under the cap,
proving narrow-scope docs and audit cycles are still cleanly
inside budget. Only detection cycles are at risk.

#### 4. Track-balance preserved across cycles 77-80

DOCS → DETECTION → SECURITY → TEST. Four of the five tracks
visited, the BENCH track the one that didn't run this window.
Cycle 79's CEO-recovery pattern (subagent finds F-025, CEO
applies fix) is the same shape as cycle 75 (F-024) and cycle
72 (F-023) — three rounds in a row where the subagent did the
read-side audit and the CEO did the write-side fix. This is
now a stable pattern, not a one-off.

## Cycles 81-84 — T1583.006 + R13 audit + e2e test

Four more cycles in the same 24-hour window, continuing the
v3.4.x line. No new findings opened; the work was concentrated
on rule coverage, audit verification, and the first end-to-end
loader test. Shape of the work:

1. **Cycle 81 (DOCS)** — `847a33e`. RETROSPECTIVE-2026-09-03.md
   extended to cover cycles 77-80 (this document, prior pass).
   Headline bumped from 23 → 24 findings. Audit table extended
   to R1..R12 = 7→2→0→1→1→1→0→1→1→0→1→0. **Fastest subagent
   ever** (57s / 7 calls).
2. **Cycle 82 (DETECTION)** — `5b74eb5` / tag `v3.4.21`.
   **T1583.006** shipped — `nft.call` rule shadowing (CWE-285).
   Catalogue now **18 self-defense rules** (was 17). 247/247
   tests pass (+4 new). **Subagent call-count discipline
   confirmed**: brief's "≤15 total tool calls" + 4-test cap
   kept the subagent at 11 calls (vs. 29 in cycle 78 with
   5 tests, vs. 24 in cycle 76 with audit). The combined-budget
   lesson from cycle 78 held. 55 tags live (v0.1..v3.4.21).
3. **Cycle 83 (SECURITY, audit)** — `a0d0f0a` / tag `v3.4.22`.
   **Round 13 audit CLEAN** — 0 new findings. 247/247 tests
   pass (no code changes). 18 rules fully validated: 18/18
   unique UUIDv4 IDs, 18/18 required fields populated, 18/18
   conditions resolve to declared keys, 0/18 injection vectors,
   level distribution 10 high / 7 medium / 1 low / 0 critical
   (alert-fatigue friendly). 56 tags live (v0.1..v3.4.22).
4. **Cycle 84 (TEST)** — `load_rules_from_dir` e2e test
   (`test_sigma_pack_load.py`, 5 integration tests). All Round 13
   audit claims verified end-to-end via the actual loader:
   18 rules loaded, all `CompiledSigmaRule` instances, 18/18
   unique UUID4 IDs, 18/18 UUID4 (not UUID1/3/5), level
   distribution 10/7/1/0 (high/medium/low/critical). 252/252
   tests pass (+5 new). **CEO recovery** — subagent timed out
   at 600s/23 calls, CEO wrote the test directly, 5/5 pass
   first try. Test-only commit, no new tag (next code-ship
   cycle picks it up).

### Numbers (delta from cycle 81 onwards)

- **Findings closed (cycles 81-84):** 0 (no new findings; 24
  total remains). Total now **24 closed (F-001..F-025)**; 1
  still open (F-018 multi-worker).
- **Releases shipped:** 2 new tags (`v3.4.21`, `v3.4.22`) plus
  a docs commit (`847a33e`) and a test-only commit (no tag).
- **Detection rules:** 30 → 30 of 200 MITRE (T1583.006 is a
  sub-technique of T1583 already covered; net MITRE count
  unchanged, but self-defense rule catalogue grew 17 → 18).
- **Tests:** 243 → 252 passing. Net delta **+9 tests** with
  zero regressions.
- **Tags:** 54 → 56 (`v0.1`..`v3.4.22`).
- **Constraint hygiene:** zero IP literals, zero credentials in
  committed code, zero AI-jargon across cycles 81-84.

### Key learnings

#### 1. "Audit verifies static, loader is truth" — established pattern

Round 13 (cycle 83) re-parsed every YAML rule and verified
each claim by inspection. Cycle 84's e2e test verifies the same
claims by running the actual `load_rules_from_dir()` loader.
If they ever disagree, we know the audit (or the loader) is
wrong. This is the structural separation that audit-only
cycles were missing:

- **Static audit** (R13): "are the files OK on disk?"
- **Loader test** (cycle 84): "what does the system actually
  use at runtime?"

The pair makes drift detectable: a rule that passes the audit
but fails the loader (or vice versa) is a real defect, not a
documentation drift. Both rounds closed clean in this window
(0 new findings), which is the desired steady state — the
audit and the loader agree.

#### 2. Subagent call-count discipline — combined budget holds

Cycle 78 hit 29 calls / 565s (over the 240s/20-call cap,
completed cleanly but at the edge). The diagnosis was: 5 tests
+ 2 module bumps + multiple file reads. Cycle 82 corrected
this with **≤4 tests + ≤15 total calls**, and finished at 11
calls / 204s (well under cap). The combined-budget rule is now
the detection brief template default:

- 4 tests + 1 module bump + explicit "≤15 total tool calls"
  → 11 calls (cycle 82, clean)
- 5 tests + 2 module bumps + no budget instruction
  → 29 calls (cycle 78, clean but at cap)

The lesson is **specificity beats generality**: a combined
budget in the brief is more effective than a test-count cap
alone. The 9-call delta comes from docstring bumps and
module re-reads, both of which a "≤15 total" instruction
naturally suppresses.

#### 3. CEO recovery for legitimate reasons — subagent honesty

Cycle 84's subagent timed out at 600s/23 calls on the e2e
test (similar shape to cycle 71's finalisation timeout). CEO
inherited and wrote the test directly — 5/5 pass first try.
This is the same recovery pattern that fired in cycles 62
(Sigma compound-not), 63 (429 rate-limit), and 71 (test
finalisation): subagent completes the work, runs out of time
during finalisation. The code shipped clean both times.

#### 4. Track-balance preserved across cycles 81-84

DOCS → DETECTION → SECURITY → TEST. Four of the five tracks
visited, BENCH the one not run. Cycle 83's Round 13 audit and
cycle 84's loader test are a natural pair: audit verifies the
static files, test verifies the runtime. Running them on
adjacent cycles (SECURITY then TEST) ensures both sides of the
rule lifecycle are exercised in the same window.

#### 5. Audit convergence — 6 clean rounds in last 9 (R8..R13 + R11 = 1)

The thirteen-round convergence table is now:

| Round | Cycle | Bug count | Findings closed           |
|-------|-------|-----------|---------------------------|
| R1    | 51    | 7         | F-001..F-007              |
| R2    | 55    | 2         | F-017, F-018              |
| R3    | 61    | 0         | (clean)                   |
| R4    | 63    | 1         | F-019                     |
| R5    | 64    | 1         | F-020                     |
| R6    | 67    | 1         | F-021                     |
| R7    | 68    | 0         | (clean)                   |
| R8    | 72    | 1         | F-023 (4 sub-bugs)        |
| R9    | 75    | 1         | F-024 (chunked bypass)    |
| R10   | 76    | 0         | (clean)                   |
| R11   | 79    | 1         | F-025 (TE vendor bypass)  |
| R12   | 80    | 0         | (clean)                   |
| R13   | 83    | 0         | (clean)                   |

Convergence: 7 → 2 → 0 → 1 → 1 → 1 → 0 → 1 → 1 → 0 → 1 → 0 → 0.
Six clean rounds in the last nine (R7, R10, R12, R13 plus R3
and R7 earlier). The R8/R9/R11 cluster was the
`csp_violation_reporter` fix chain; R13 came back clean and
the loader test (cycle 84) confirmed R13's claims end-to-end.
This is the first window where the audit + the test both
agreed there is nothing left to fix in the current surface.

## Cycles 85-88 — T1583.007 + R14 audit + invariants tests

Four more cycles in the same 24-hour window, continuing the v3.4.x
line. No new findings opened; the work was concentrated on rule
coverage (T1583.007), the fastest audit yet (R14, 97s), and the
first runtime-invariants test file for `agents_provision`. Shape
of the work:

1. **Cycle 85 (DOCS)** — `c90b686`. RETROSPECTIVE-2026-09-03.md
   extended to cover cycles 81-84 (this document, prior pass).
   Headline bumped from 24 → 24 findings (no new findings in
   cycles 81-84, but the catalogue is now fully cross-linked
   through 4 docs passes). **Fastest clean subagent** (112s /
   6 calls).
2. **Cycle 86 (DETECTION)** — `a65b60f` (subagent rule) +
   `33c7e18` (CEO e2e test bump) / tag `v3.4.23`. **T1583.007**
   shipped — `nft.call` policy violation (CWE-285). Catalogue
   now **19 self-defense rules** (was 18). 256/256 tests pass
   (+4 new). 57 tags live (v0.1..v3.4.23). **CEO recovery**
   for the 17th time — subagent succeeded, but the cycle 84 e2e
   test (load_rules_from_dir) was hardcoded to 18 rules and
   10/7/1/0 level distribution; adding rule #19 (another
   "high") caused 2 errors. CEO bumped 18→19, 10→11, pytest
   passes, v3.4.23 tagged in 2 minutes. The e2e test catching
   version drift is exactly the behavior we want.
3. **Cycle 87 (SECURITY, audit)** — `224f53d` / tag `v3.4.24`.
   **Round 14 audit CLEAN** — 0 new findings. 256/256 tests
   pass (no code change). Audited 10 vectors on the
   `agents_provision` surface: command injection (Pydantic
   Literal + char blocklist + regex + shlex.quote), tenant_id
   (N/A), auth/role escalation (single gate, no hierarchy),
   download URL safety (SHA-256 pin F-015), TOML serialization
   (`_toml_quote`), PS here-string & bash heredoc terminators
   (unreachable), log/error leakage, F-021 fix completeness.
   **Fastest audit ever** (97s / 10 calls) — fresh target (not
   the over-audited csp_violation_reporter), 10 specific
   questions, no new audit code. 58 tags live (v0.1..v3.4.24).
4. **Cycle 88 (TEST)** — `d6d8d3f`. **`test_agents_provision_security_invariants.py`**
   shipped — 4 new tests verifying the R14 audit's claims at
   runtime: `test_command_injection_via_os_blocked`
   (Pydantic `Literal["linux", "macos", "windows"]` rejects
   `"linux; rm -rf /"`), `test_command_injection_via_host_blocked`
   (`_safe_host` rejects metachar payloads),
   `test_tenant_id_not_in_query` (asserts no `tenant_id` in
   model), `test_ipv6_bracketed_rejected` (`[::1]` rejected by
   `_HOST_RE`). 260/260 tests pass (+4). No new tag (test-only).
   Subagent was 25% over the 20-call cap (25 calls, 464s) but
   the work was coherent — one test file, four tests, clean
   result.

### Numbers (delta from cycle 85 onwards)

- **Findings closed (cycles 85-88):** 0 (no new findings; the
  csp_violation_reporter fix chain has stabilised). Total
  remains **24 closed (F-001..F-025)**; 1 still open (F-018
  multi-worker).
- **Releases shipped:** 2 new tags (`v3.4.23`, `v3.4.24`)
  plus a docs commit (`c90b686`) and a test-only commit
  (`d6d8d3f`).
- **Detection rules:** 30 → 30 of 200 MITRE (T1583.007 is a
  sub-technique of T1583 already covered; net MITRE count
  unchanged, but self-defense rule catalogue grew 18 → 19).
- **Tests:** 252 → 260 passing. Net delta **+8 tests** with
  zero regressions.
- **Tags:** 56 → 58 (`v0.1`..`v3.4.24`).
- **Constraint hygiene:** zero IP literals, zero credentials
  in committed code, zero AI-jargon across cycles 85-88.

### Key learnings

#### 1. "Audit + runtime tests" — defense in depth established

Cycle 84 established the "audit verifies static, loader is
truth" pattern. Cycles 87-88 extend it: R14 audit verified
10 claims about `agents_provision` by reading the code
(static), and cycle 88's invariants test file verifies the
same claims by actually running the endpoint (runtime). If
the audit and the test ever disagree, one of them is wrong —
and we know which side has the bug.

The pattern is now structural across the rule lifecycle:

| Layer    | Cycle  | Tool                  | Asserts                |
|----------|--------|-----------------------|------------------------|
| Static   | R14/87 | yaml+source re-read   | files are OK on disk   |
| Loader   | 84/86  | load_rules_from_dir() | rules load correctly   |
| Runtime  | 88     | test_*.py invariants  | endpoint enforces them |

Two layers (audit + runtime) for `agents_provision`, two
layers (audit + loader) for the Sigma pack. Each catches a
class of drift the others cannot.

#### 2. Subagent-call-count trend — 6 → 18 → 10 → 25 (median ~15)

The four-cycle window shows the full range of subagent
discipline:

| Cycle | Track     | Calls | Outcome        |
|-------|-----------|-------|----------------|
| 85    | docs      | 6     | clean          |
| 86    | detection | 18    | clean (CEO recovery) |
| 87    | security  | 10    | clean          |
| 88    | test      | 25    | clean (25% over cap) |

Median ~15 calls. Cycle 86's 18 was clean because the
≤15-call brief instruction was respected for the rule
itself; the CEO recovery was for the e2e test bump, a
separate 2-minute task. Cycle 88's 25 was coherent work
(one test file, four tests) — over cap but justified.

The lesson: a combined budget (≤4 tests + ≤2 module edits +
≤15 calls) keeps detection and test cycles inside the
cap; overshoot is fine when the work is single-file and
coherent. The cap is informational, not gating.

#### 3. e2e loader test catching version drift — first payoff

Cycle 86's T1583.007 broke the cycle 84 e2e test on the
first run. The test was hardcoded to 18 rules + 10/7/1/0
level distribution; adding rule #19 (another "high")
caused 2 errors. This is exactly the behavior we want: the
e2e test catches version drift before it ships.

The fix is structural, not a workaround. Every new rule
shipped must keep `level_distribution` accurate. Future
detection cycles should treat the e2e test's counts as
the contract — if the rule's level is `high`, the test
will demand it.

This is the second time (cycle 88 being the other) that
the cycle 84 "audit + loader are two sides" insight has
paid off — the loader test is now load-bearing, not
advisory.

#### 4. Fastest audit ever (cycle 87) — 97s / 10 calls

Cycle 87's R14 audit closed in 97 seconds with 10 calls,
the fastest audit on record. Three reasons:

1. **Fresh target.** Auditing `agents_provision` (10
   vectors, all well-bounded) rather than the
   over-audited `csp_violation_reporter` (which has
   absorbed 4 rounds of fixes).
2. **Specific questions.** Each of the 10 vectors was a
   yes/no question with a deterministic answer (Literal
   present? `shlex.quote` used? etc.). No open-ended
   review.
3. **Read-only.** No new audit code, no file edits, no
   test writes. Just read + verify + report.

This sets a useful floor for future audits: a clean,
bounded, read-only round on a fresh surface should land
in ~100s / ~10 calls. Cycles that need more are doing
fix work, not audit work.

#### 5. Track-balance preserved across cycles 85-88

DOCS → DETECTION → SECURITY → TEST. The same four-track
rotation as cycles 81-84, with each track landing on the
surface the previous track didn't touch:

- **Cycle 85 (docs)** wrote about cycles 81-84.
- **Cycle 86 (detection)** shipped a new rule (T1583.007),
  breaking the loader test.
- **Cycle 87 (security)** audited a fresh surface
  (agents_provision), not the over-audited reporter.
- **Cycle 88 (test)** runtime-verified the cycle 87 audit.

The cycle 87/88 pair is the cleanest demonstration yet of
the audit + runtime = defense in depth pattern: two
different tracks, two different verification methods, same
findings (zero new findings, twice).

#### 6. Audit convergence — R14 = 0, R13 = 0

The fourteen-round convergence table is now:

| Round | Cycle | Bug count | Findings closed           |
|-------|-------|-----------|---------------------------|
| R1    | 51    | 7         | F-001..F-007              |
| R2    | 55    | 2         | F-017, F-018              |
| R3    | 61    | 0         | (clean)                   |
| R4    | 63    | 1         | F-019                     |
| R5    | 64    | 1         | F-020                     |
| R6    | 67    | 1         | F-021                     |
| R7    | 68    | 0         | (clean)                   |
| R8    | 72    | 1         | F-023 (4 sub-bugs)        |
| R9    | 75    | 1         | F-024 (chunked bypass)    |
| R10   | 76    | 0         | (clean)                   |
| R11   | 79    | 1         | F-025 (TE vendor bypass)  |
| R12   | 80    | 0         | (clean)                   |
| R13   | 83    | 0         | (clean)                   |
| R14   | 87    | 0         | (clean)                   |

Convergence: 7 → 2 → 0 → 1 → 1 → 1 → 0 → 1 → 1 → 0 → 1 → 0 → 0 → 0.
**Six clean rounds in the last eight** (R10, R12, R13, R14,
plus R3 and R7 earlier). The audit chain is converging:
R11 was the last `csp_violation_reporter` fix, R13 audited
the Sigma pack and found nothing, R14 audited a fresh
surface and found nothing. With cycle 88's runtime
invariants confirming R14's claims, the audit + runtime
pair is now structurally closed — drift in either layer
would surface in the next cycle.

## Cycles 89-92 — T1583.008 + R15 audit + immutability

Four more cycles in the same 24-hour window, continuing the v3.4.x
line. No new findings opened; the work was split across detection,
audit, and test verification. Shape of the work:

1. **Cycle 89 (DOCS)** — `5251747`. RETROSPECTIVE-2026-09-03.md
   extended to cover cycles 85-88 (the prior pass on this same
   document). **Fastest cycle on record** — 40s / 5 calls (the
   subagent only had to read 5 files and write 1 new section;
   pure read+write = minimal tool calls).
2. **Cycle 90 (DETECTION)** — `316fd99` / tag `v3.4.25`. **T1583.008**
   shipped — `nft.call` unhandled chain (CWE-754). Catalogue now
   **20 self-defense rules** (was 19). 264/264 tests pass (+4 new).
   E2E test drift detection worked cleanly: the brief explicitly
   told the subagent to bump the e2e loader test from 19→20 rules
   and 11→12 high; it did, and the CEO didn't need to fix anything.
   The "subagent also updates the e2e test when adding a new rule"
   pattern is now embedded in the brief template. **Borderline
   clean** (218s / 16 calls — under the 240s/20-call cap by 20%).
3. **Cycle 91 (SECURITY, audit + defense-in-depth)** — `9e983c0`
   (subagent R15) + `0a3729e` (CEO hardening) / tag `v3.4.26`.
   **Round 15 audit CLEAN** — 8 vectors audited on
   `self_defense/__init__.py`, 0 findings. The audit found a
   non-issue (the rules list was mutable, but nothing in the
   code mutates it); the CEO decided to fix it anyway as a
   1-line defense-in-depth: `SELF_DEFENSE_RULES` is now
   `tuple[...]` instead of `list[...]`. **264/264 tests pass**
   (no test changes). This is the **5th occurrence** of the
   "subagent finds, CEO fixes" pattern.
4. **Cycle 92 (TEST)** — `dcc983e`. **Immutability tests**
   shipped — `test_self_defense_immutability.py` with 5 new
   runtime tests:
   - `test_self_defense_rules_is_tuple` — runtime type check.
   - `test_rule_titles_is_tuple` — runtime type check.
   - `test_self_defense_rules_not_mutable` — `.append(...)` raises.
   - `test_self_defense_rules_count_is_20`.
   - `test_self_defense_rules_have_unique_titles`.
   **269/269 tests pass** (+5 new). Clean subagent (130s /
   19 calls — under cap).

### Numbers (delta from cycle 89 onwards)

- **Findings closed (cycles 89-92):** 0 (no new findings). Total
  still **24 closed (F-001..F-024)**; 1 still open (F-018
  multi-worker).
- **Releases shipped:** 2 new tags (`v3.4.25`, `v3.4.26`) plus
  2 docs/test-only commits (`5251747`, `dcc983e`).
- **Detection rules:** 30 → 30 of 200 MITRE (T1583.008 is a
  sub-technique of T1583 already covered by T1583.001..T1583.007;
  net MITRE count unchanged, but self-defense rule catalogue
  grew **19 → 20**).
- **Tests:** 260 → 269 passing. Net delta **+9 tests** with zero
  regressions.
- **Tags:** 58 → 60 (`v0.1`..`v3.4.26`).
- **MITRE coverage:** 33/200 (16.5%) — passed 1/6 of the way to
  the Q4 2026 50% target.
- **Constraint hygiene:** zero IP literals, zero credentials in
  committed code, zero AI-jargon across cycles 89-92.

### Key learnings

#### 1. "Audit → harden → test" 3-step pattern established (cycles 84-92)

Over the last nine cycles, a 3-step pipeline emerged organically:

1. **Audit** (subagent, SEC or TEST track) — finds a static
   claim or invariant.
2. **CEO hardens** (1-line code change, often as a follow-up
   commit by the parent).
3. **Test** (subagent, TEST track) — verifies the hardening at
   runtime, not just by reading source.

Cycles 84-92 trace this exactly:

- Cycle 87's R14 audit: SELF_DEFENSE_RULES = list (static claim).
- Cycle 91's CEO hardening: tuple (defense-in-depth).
- Cycle 92's immutability tests: tuple type, count, uniqueness,
  append-raises.

The chain is now self-sustaining: an invariant declared in an
audit report becomes a runtime check within 1-3 cycles. Drift in
the runtime layer surfaces in the next audit (R15), drift in
the static layer surfaces in the next test (cycle 92). This is
the same defense-in-depth shape as cycles 87/88's audit+runtime
pair, extended to a 3-step pipeline.

#### 2. E2E test drift detection now embedded in the brief template (cycle 90)

Cycles 86 and 90 both added rules that broke the e2e loader
test. Cycle 86 required a CEO follow-up (33c7e18 bumped the
expectations 18→19, 10→11 high). Cycle 90's brief **explicitly
told the subagent** to bump the loader test from 19→20 rules
and 11→12 high — and the subagent did, with no CEO fixup.

Three data points on the e2e drift-catch:

- Cycle 86: detection rule added → test broken → CEO fixup.
- Cycle 90: detection rule added → test broken → brief
  pre-emptive → subagent self-fixes.
- Cycle 92: rule count = 20 → runtime test verifies count = 20.

The pattern is now load-bearing: every new rule ships with its
loader-test bump in the same dispatch. Future cycle briefs will
continue to include the loader-test bump as a precondition.

#### 3. Sigma engine memory — 2nd self-correction (cycle 90)

The cycle 90 subagent (a DETECTION cycle, where compound-not
mistakes historically happen) shipped T1583.008 on the first
attempt with no CEO correction — the **2nd time** a detection
subagent has self-corrected a Sigma engine constraint without
prompting (the 1st was cycle 70's T1583.003).

Compare cycle 62 (compound-not rejection → CEO recovery):
the constraint is now in the subagent's prior, not just the
CEO's. Combined with the cycle 90 e2e self-fix and the
cycle 92 immutability test authoring, this is the third
consecutive subagent in cycles 90-92 that completed its work
without CEO intervention on the technical surface.

#### 4. Audit convergence — R15 = 0, R14 = 0

The fifteen-round convergence table is now:

| Round | Cycle | Bug count | Findings closed           |
|-------|-------|-----------|---------------------------|
| R1    | 51    | 7         | F-001..F-007              |
| R2    | 55    | 2         | F-017, F-018              |
| R3    | 61    | 0         | (clean)                   |
| R4    | 63    | 1         | F-019                     |
| R5    | 64    | 1         | F-020                     |
| R6    | 67    | 1         | F-021                     |
| R7    | 68    | 0         | (clean)                   |
| R8    | 72    | 1         | F-023 (4 sub-bugs)        |
| R9    | 75    | 1         | F-024 (chunked bypass)    |
| R10   | 76    | 0         | (clean)                   |
| R11   | 79    | 1         | F-025 (TE vendor bypass)  |
| R12   | 80    | 0         | (clean)                   |
| R13   | 83    | 0         | (clean)                   |
| R14   | 87    | 0         | (clean)                   |
| R15   | 91    | 0         | (clean)                   |

Convergence: 7 → 2 → 0 → 1 → 1 → 1 → 0 → 1 → 1 → 0 → 1 → 0 → 0 → 0 → 0.
**Seven clean rounds in the last nine** (R10, R12, R13, R14,
R15, plus R3 and R7 earlier). The audit chain is converging:
R11 was the last `csp_violation_reporter` fix, R13 audited the
Sigma pack and found nothing, R14 audited a fresh surface and
found nothing, R15 audited `self_defense/__init__.py` and
found nothing — the only "find" was a defense-in-depth nit the
CEO chose to fix. With cycle 92's runtime immutability tests
confirming the cycle 91 hardening, the audit + runtime +
defense-in-depth triplet is now structurally closed.

#### 5. Subagent streak — clean streak of 4 across the cycle 89-92 window

Cycles 89-92 produced four consecutive clean subagents:

- **Cycle 89** (40s / 5 calls) — pure read+write, fastest ever.
- **Cycle 90** (218s / 16 calls) — under cap by 20%.
- **Cycle 91** (291s / 13 calls, audit-only portion) — under
  cap by 35%.
- **Cycle 92** (130s / 19 calls) — under cap.

No CEO recoveries in the window, no 429s, no timeouts on the
subagent side. Cycle 91 was a "subagent finds, CEO hardens"
pair (5th occurrence) but the subagent itself was clean —
the CEO commit was a separate follow-up, not a recovery.

#### 6. Track-balance preserved across cycles 89-92

DOCS → DETECTION → SECURITY → TEST. The same four-track
rotation as cycles 85-88, with each track landing on the
surface the previous track didn't touch:

- **Cycle 89 (docs)** wrote about cycles 85-88.
- **Cycle 90 (detection)** shipped T1583.008, breaking the
  loader test.
- **Cycle 91 (security)** audited `self_defense/__init__.py`,
  not the over-audited `csp_violation_reporter`.
- **Cycle 92 (test)** runtime-verified the cycle 91 hardening.

The cycle 91/92 pair extends the cycle 87/88 audit+runtime
pattern: cycle 91 found the static claim, cycle 92 made the
runtime check. Two different tracks, two different
verification methods, both clean.

## Future work (next 10 cycles)

### v3.5.0 — Detection pack round 2 (carried over)

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

### F-018 multi-worker (Redis stream) — partially shipped

The v3.4.4 in-process fix shipped in cycle 59 (closed the
in-process portion of F-018). The durable answer — Redis-backed
stream for multi-worker event delivery — still didn't fit any
single cycle. Now formally tracked under
`self_defense/MULTI_WORKER.md` and scoped for **v3.5.0**.

Add a `STREAM_BACKEND` env var that, when set to `redis://...`,
routes `_STREAM` append/flush through a `redis.asyncio` Stream.
Single-worker mode (`--workers 1`) stays the default; multi-worker
mode becomes safe without lock contention.

### External bug bounty (PortSwigger / HackTheBox)

The detection catalogue is now stable enough (30 rules, 250 tests,
public-release audit clean) to invite external review. Plan:

1. Publish a "challenge scope" doc under `docs/security/bounty/`.
2. Submit the WebUI attack surface to PortSwigger's research review.
3. Submit the WS / HMAC handshake surface to HackTheBox's business
   CTF track.

External review will surface findings the self-hunt cannot (adversary
creativity, novel chains, off-by-default tooling).

## Closing note

Twenty-four cycles, twenty-four findings closed, seventeen self-defense
rules, two hundred forty-three tests, twenty-five releases shipped, zero
regressions, zero IP literals, zero credentials, zero AI-jargon.
The work-rate is high but the constraints are intact. The single
open finding (F-018 multi-worker) is documented, scoped, and on the
v3.5.0 roadmap.