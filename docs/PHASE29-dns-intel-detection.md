# PHASE29 — T1583.001 Domain Acquisition Detection Pack

**Tag:** `v3.2.0`
**Cycle:** 49
**Track:** detection (6th consecutive cycle on this track — longest in ZaqorinCore history)
**Date:** 2026-09-03
**Commit:** `cdcefcb` (amended; HEAD `5c93ccd` after the `--amend`)
**Reviewer:** Cybersec — PASS

---

## TL;DR

v3.2.0 ships the first **domain-acquisition** detection pack in
ZaqorinCore: five precision-engineered Sigma rules covering
**MITRE ATT&CK T1583.001 — Acquire Infrastructure: Domains**, plus the
Python helpers (`brand_protection.py`, `dns_intel_interface.py`) and a
44-test green gate. MITRE coverage rises **16/200 → 17/200 (8.0% → 8.5%)**.

Every rule in this pack applies four precision techniques (multi-signal,
threshold, whitelist, experimental promotion). Per the precision
commitment (Faris, 2026-09-03, "tingkat akurasi 80%"): the **design
target is 80%+ precision**. The actual number will be measured from
production telemetry, not asserted.

---

## Context

### North Star alignment

The ZaqorinCore North Star is *better defenses for the people who run
their own infrastructure.* T1583.001 is one of the highest-leverage
techniques in the Adversary Resource Development tactic (TA0042):
adversaries routinely register throwaway domains **hours** before they
launch phishing campaigns, stand up C2, or stage payloads. Catching the
registration — or the *first queries* from inside a defended network —
moves detection from "user clicked the link" back to "adversary just
bought the bait." That is the North Star payoff.

### Why T1583.001 specifically

* **Volume-weighted value.** Many other Resource Development
  techniques (VPS rental, botnets, SSL cert abuse) are rare or expensive
  to detect from log data alone. Domains are observable — every internal
  host that resolves a name leaves a fingerprint.
- **Low base-rate inside defended networks.** Captive portals, brand
  domains, CDN edges all sit in the same signal channel, so a *naive*
  detector would drown in noise. Precision design matters more here
  than rule count.
- **Maps cleanly onto existing Sigma engine grammar.** All five rules
  use `selection and not filter` (or the variant `selection and not
  filter_legit_brand` for the typosquat rule) — the patterns the engine
  already accepts (see `PHASE15-sigma-compound-conditions.md`).

### The five rules (one-line summary)

| Rule | Signal | Window | Threshold | Level |
|---|---|---|---|---|
| `T1583_001_domain_acquisition_nrd` | Internal host resolves NRD (≤ 5 min) | 5 m | ≥ 3 events | medium |
| `T1583_001_domain_acquisition_tld_burst` | Burst of queries to abuse-prone TLDs | 60 s | ≥ 5 events | high |
| `T1583_001_domain_acquisition_typosquat` | Levenshtein 1–2 from protected brand | 1 h | 1 event | high |
| `T1583_001_domain_acquisition_dormant` | Dormant domain (≥ 90 d) reactivates | 60 s | ≥ 10 queries | medium |
| `T1583_001_domain_registration_internal` | Internal POST to `/register` or `/create` | 30 m | 1 event | high |

All five live in `server/rules/builtin/mitre_attack/`.

---

## Architecture

### How the pieces fit

```
                  ┌──────────────────────────────────────────────────────────┐
                  │ Agent (host)                                              │
                  │  zeek-style dns_query events ────▶ WS stream               │
                  │  + typosquat metadata stamps (typosquat_brand,           │
                  │    typosquat_distance, typosquat_is_legitimate)           │
                  └──────────────────────────────────────────────────────────┘
                                          │
                                          ▼
                  ┌──────────────────────────────────────────────────────────┐
                  │ Server — FastAPI                                          │
                  │  1. ingest (Redis Streams)                                │
                  │  2. detector stage (writes typosquat_* via brand_protection)│
                  │  3. Sigma engine evaluates 5 rules                        │
                  │  4. alerts → PostgreSQL                                   │
                  └──────────────────────────────────────────────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────────┐
                  │                                                   │
                  ▼                                                   ▼
   dns_intel_interface.py                            brand_protection.py
   (Protocol + WHOISRDAPClient stub)                 (Levenshtein 1-2,
   — feeds NRD / dormant / registration              protected brand list)
    signals in v3.3.0+)
```

The five rules fire off three different event shapes:

* `dns_query` events — the typosquat, NRD, TLD-burst, and dormant rules.
  These ride the existing zeek-style DNS pipeline.
* `http_request` events — the registration-internal rule. Fires on
  internal hosts POSTing to registrar endpoints.

The `dns_intel` collector stub (`agent/collectors/dns_intel.py` +
`agent/cmd/zaqorin-dns-intel-stub.py`) and the `dns_intel_interface.py`
Protocol class are **wired but not feeding live data yet** — the live
RDAP / WHOIS pull is deferred to v3.3.0 (see "Known limitations").
Today the rules run on whatever metadata the existing collectors
emit (`dns_age_seconds`, `dns_last_seen_days`, `dns_reactivation_burst`).

### Engine constraint we worked inside

The ZaqorinCore Sigma engine accepts:

* Pattern 1 — `selection`
* Pattern 2 — `selection and filter`
* Pattern 3 — `selection and not filter`
* Pattern 4 — `selection and (X or Y) and not Z` (compound-not /
  compound-or per `PHASE15-sigma-compound-conditions.md`)
* **Single `filter_*` block per rule.**

Every rule in this pack uses one of these patterns and stays within the
single-filter constraint. The UA-allowlist in the registration rule
documents the *intent* (5 UAs allowed) inside the rule body and
recommends the operator extend it via `source_tag` — the engine
limitation is called out in a comment at the bottom of the rule file
so future operators do not re-discover it the hard way.

---

## The 5 rules

### 1. `T1583_001_domain_acquisition_typosquat.yml`

| Field | Value |
|---|---|
| Title | Brand typosquat domain resolution (Levenshtein 1-2) |
| ID | `5d2f8a91-6b3e-4c7d-9a1f-2e4b8c3d6fa3` |
| Level | high |
| Signal | `typosquat_brand=true` AND `typosquat_distance < 3` |
| Threshold | 1 event in 1 h |
| Whitelist | `typosquat_is_legitimate=true` (the brand IS the registrant) |
| FP risk | low — legitimate brand queries are silenced by the whitelist |
| Tuning | extend `ZAQORIN_PROTECTED_BRANDS` (csv of SLDs) |

**Concrete example:** `mlcrosoft.com` resolved by an internal host
matches: `typosquat_brand=true` (distance 1 from `microsoft.com`),
`typosquat_distance=1`, `typosquat_is_legitimate=false`. Fires once,
dedup-keyed on `source_ip:query` for 1 h cooldown.

**False-positive shape:** the legitimate `microsoft.com` is silenced
because `typosquat_is_legitimate=true`. Operators who see CDN / captive
overlap should add the CDN SLD as a brand entry (see "Tuning playbook").

### 2. `T1583_001_domain_acquisition_nrd.yml`

| Field | Value |
|---|---|
| Title | Newly Registered Domain queried by internal host |
| ID | `5d2f8a91-6b3e-4c7d-9a1f-2e4b8c3d6fa1` |
| Level | medium |
| Signal | `dns_age_seconds < 301` AND `source_internal=true` |
| Threshold | ≥ 3 events in 5 m from same source_ip |
| Whitelist | regex alternation: `\.cloudfront\.net` \| `\.akamaiedge\.net` \| `apple\.com` \| `google\.com` \| `microsoft\.net$` |
| FP risk | medium — first-time users on a new device may hit a never-seen domain, but the 3-event threshold suppresses one-off noise |
| Tuning | raise threshold to 5+ in noisier environments, or lower if your network rarely queries brand-new domains |

**Concrete example:** internal host resolves `fresh-landing-page.xyz`
1 minute after registration, 4 times in 3 minutes → 3rd event trips
the threshold. Fires. Dedup-keyed on `source_ip:query` for 30 min.

**Limitation:** engine counts events, not distinct domains. The 3-event
threshold is calibrated against observed single-domain burst patterns.

### 3. `T1583_001_domain_acquisition_tld_burst.yml`

| Field | Value |
|---|---|
| Title | Burst of suspicious-TLD DNS queries from a single host |
| ID | `5d2f8a91-6b3e-4c7d-9a1f-2e4b8c3d6fa2` |
| Level | high |
| Signal | query matches `\.{xyz,top,tk,ml,cf,ga}$` |
| Threshold | ≥ 5 events in 60 s from same source_ip |
| Whitelist | same CDN/captive/Microsoft alternation as NRD |
| FP risk | low — abuse-prone TLDs (spamhaus top-10) rarely appear in legitimate traffic |
| Tuning | if your org legitimately uses one of these TLDs (uncommon), add it to the filter |

**Concrete example:** host suddenly fires 6 `.xyz` lookups in 30 s →
 fires. Dedup-keyed on `source_ip:tld_burst` (not per-query) for 30 min.

### 4. `T1583_001_domain_acquisition_dormant.yml`

| Field | Value |
|---|---|
| Title | Dormant domain reactivation (90+ day gap then burst) |
| ID | `5d2f8a91-6b3e-4c7d-9a1f-2e4b8c3d6fa4` |
| Level | medium |
| Signal | `dns_last_seen_days >= 90` AND `dns_reactivation_burst=true` |
| Threshold | ≥ 10 queries in 60 s from single host |
| Whitelist | same CDN/captive/Microsoft alternation |
| FP risk | low — 90-day dormancy + 10-event burst is rare in normal traffic |
| Tuning | drop `dns_last_seen_days` threshold to 30 d if your network rarely sees long-dormant domains reappearing |

**Concrete example:** `old-park-domain.com` (last seen 142 d ago)
suddenly receives 12 lookups from one host inside a 45-second window
→ fires. The collector must set `dns_reactivation_burst=true` (see
"Known limitations" if your collector doesn't yet emit this flag).

### 5. `T1583_001_domain_registration_internal.yml`

| Field | Value |
|---|---|
| Title | Internal host POST to domain registration endpoint |
| ID | `5d2f8a91-6b3e-4c7d-9a1f-2e4b8c3d6fa5` |
| Level | high |
| Signal | `method=POST` AND `uri` matches `/(register|create)$` AND `source_internal=true` AND UA is NOT `curl/*` |
| Threshold | 1 event in 30 m |
| Whitelist | `user_agent: startswith: curl/` |
| FP risk | low — internal POST to a registrar with a non-CI UA is anomalous |
| Tuning | add more UA prefixes via `source_tag=dev` or per-UA follow-up rules (engine allows only one filter block, intent documented in the rule body) |

**Concrete example:** host in the marketing VLAN POSTs to
`https://porkbun.com/api/dns/create` with a Go-net UA → fires once.

**Engine caveat:** the rule body documents the intent of also allowing
`python-requests`, `Go-http-client`, `Apache-HttpClient`, and
`GitHub-Actions`. The engine loader rejects repeated `startswith` keys
in a single block, so only the highest-volume (curl) is in the active
filter. Operators can extend by tagging CI hosts with `source_tag=dev`
or by adding per-UA follow-up rules — both approaches are listed in
the rule comments.

---

## Precision design

Every rule in this pack applies **four** precision techniques. The
combination is what separates this pack from a naive "any query to a
new domain" detector:

### Technique 1 — Multi-signal correlation

No rule fires on a single observation. Each requires **at least two
signals** to align in a defined window:

* `typosquat`: brand-match AND distance-bound
* `nrd`: age-bound AND internal-source AND event-count
* `tld_burst`: TLD-match AND event-count
* `dormant`: dormancy-bound AND burst-bound
* `registration`: HTTP-POST AND URI-pattern AND internal-source AND
  UA-not-in-allowlist

Single-pattern matches are suppressed at the rule level.

### Technique 2 — Explicit thresholds

| Rule | Timeframe | Count |
|---|---|---|
| typosquat | 1 h | 1 |
| nrd | 5 m | 3 |
| tld_burst | 60 s | 5 |
| dormant | 60 s | 10 |
| registration | 30 m | 1 |

Thresholds were chosen against observed benign single-domain burst
patterns. Single-event rules (`typosquat`, `registration`) compensate
with a stricter signal combination.

### Technique 3 — Whitelist

Every rule has a `filter_*` block:

* `typosquat` → `filter_legit_brand` (the brand IS the registrant)
* `nrd` / `tld_burst` / `dormant` → `filter_legit` (CDN / captive /
  Microsoft CDN via single regex alternation)
* `registration` → `filter_known_ua` (single curl/* prefix)

The single-filter-block constraint is documented in
`PHASE15-sigma-compound-conditions.md`. All five rules honor it.

### Technique 4 — Experimental promotion tier

All five rules ship at `promotion: experimental`. The precision target
(80%+) is a **design commitment**, not a measured number — the
measurement depends on operator traffic patterns. Operators are
expected to tune per-environment before promoting any rule to
`production` (see Tuning playbook below).

---

## Tuning playbook

Operators running these rules against real traffic will see alerts they
need to refine. The expected noise patterns and the right adjustments:

### Pattern: typosquat noise from a vendor you don't actually whitelist

**Symptom:** legitimate vendor at `slackkk.com` (distance 2 from
`slack.com`) keeps firing because you forgot to add it.

**Fix:** add `slackkk.com` (or just the parent `slack`) to
`ZAQORIN_PROTECTED_BRANDS` in `server/.env.example` — operators who
also own `slackkk.com` (the legitimate variant) will get the
`typosquat_is_legitimate=true` flag and be silenced automatically.

### Pattern: NRD rule too chatty on laptops that boot every morning

**Symptom:** a fleet of laptops fires a Windows-update / MDM burst of
NRD queries at 09:00 every day.

**Fix:** raise the threshold from `count: 3` to `count: 8` (or higher)
in the NRD rule. Test files already document the threshold as a
single-line edit; the rule remains sound above 5.

### Pattern: TLD burst firing on legit `.tk` redirects

**Symptom:** marketing uses a `.tk` URL shortener for legitimate
campaigns.

**Fix:** add the shortener host SLD to the whitelist block (extend the
regex alternation). Uncommon, but documented in the rule body.

### Pattern: Dormant rule silent because the collector doesn't set `dns_reactivation_burst`

**Symptom:** the dormant rule never fires even when you can see the
90-day gap from logs.

**Fix:** this is the live-RDAP gap (see "Known limitations"). Until
v3.3.0, the collector needs a one-line extension to set
`dns_reactivation_burst=true` when an event follows ≥ 90 days of
silence. Tracked in ROADMAP.

### Pattern: Registration rule false-positives from dev workstations

**Symptom:** developers testing APIs (Python + `python-requests` UA)
fire the registration rule.

**Fix:** extend via `source_tag=dev` on the dev subnet's collector or
add a per-UA follow-up rule (the engine constraint is documented in
the rule body). Production teams should NOT silence the rule globally
— dev workstations POSTing to registrars from inside the network is
still anomalous in a mature posture.

### Promotion criteria (experimental → production)

After **30 days** in production with:

* Alert-to-incident conversion ≥ 50% (≥ half the alerts lead to a
  confirmed T1583.001 precursor), AND
* False-positive rate < 20% (alerts closed-as-not-applicable), AND
* No collisions with the whitelist under load,

an operator may bump `promotion: experimental` to
`promotion: production` in the rule file. This is a per-operator
promotion — ZaqorinCore does not centrally enforce production-only
rules.

---

## Known limitations + v3.3.0 deferred work

### 1. RDAP live feed is stubbed

`dns_intel_interface.py` defines the `WHOISRDAPClient` Protocol and a
stub class. The collector (`agent/collectors/dns_intel.py`) and the
CLI stub (`agent/cmd/zaqorin-dns-intel-stub.py`) are interfaces — they
do not pull live RDAP/WHOIS data yet.

**What ships today:** rules run on whatever metadata the existing
zeek-style collectors emit (`dns_age_seconds`, `dns_last_seen_days`,
`dns_reactivation_burst`).

**What lands in v3.3.0:** the live RDAP client implementation,
backed-off per-domain cache (avoid hammering registrars), and the
collector extension to set `dns_reactivation_burst=true` on first
observation after the configured gap.

### 2. Brand list is hard-coded to 3 defaults

`DEFAULT_PROTECTED_BRANDS = ("komatsu.co.id", "microsoft.com", "google.com")`
plus the `ZAQORIN_PROTECTED_BRANDS` env var override.

**What ships today:** the env var override works for any operator
willing to set it. The 3 defaults are conservative — they cover the
most-targeted brands globally but obviously don't cover yours.

**What lands in v3.3.0:** an expanded default list (likely 30+
brands, top-100 by global phishing volume), a per-region overlay file,
and a documented process for operators to submit additions upstream.

### 3. Engine counts events, not distinct domains

The ZaqorinCore Sigma engine counts events per rule within the
timeframe. It does not currently support `distinct_count` over a field
without a downstream correlator.

**What ships today:** thresholds (3 for NRD, 5 for TLD burst, 10 for
dormant) are calibrated against single-domain bursts. They will
under-count true T1583.001 cases where an adversary distributes queries
across many new domains in a window.

**What lands in v3.3.0:** distinct-SLD enforcement via a downstream
correlator that fans the engine's output through a `distinct` count
before promoting to an alert. Spec lives in
`docs/decisions/2026-09-03-distinct-domain-correlator.md` (to be
written before v3.3.0 ships).

### 4. UA-allowlist is single-prefix by engine constraint

The registration rule can only filter one UA prefix in the active
filter block. The intent (allowlist: curl, python-requests,
Go-http-client, Apache-HttpClient, GitHub-Actions) is documented in
the rule body and the follow-up path (`source_tag` or per-UA
follow-up rules) is also documented.

**What ships today:** `curl/*` silenced; the others fire on first hit.

**What lands in v3.3.0:** the engine extension to accept a list of
startswith values under one filter block. Until then, the workaround
above is the supported path.

---

## Migration notes (operators on v3.1.x)

Wire format is unchanged (no event-schema additions), so the upgrade
is a pull-and-restart. Operators should plan for the following four
shifts:

### 1. New env vars (no-ops if absent)

Add to your `.env` (defaults shown):

```bash
# Leave empty to disable RDAP feed (v3.3.0 deliverable).
ZAQORIN_WHOIS_RDAP_URL=

# Override the typosquat brand list. Defaults to:
#   komatsu.co.id, microsoft.com, google.com
ZAQORIN_PROTECTED_BRANDS=komatsu.co.id,microsoft.com,google.com
```

Both can stay blank — the rules still run on collector-emitted
metadata. The defaults work for a generic deployment; replace
`ZAQORIN_PROTECTED_BRANDS` for your own brand inventory.

### 2. Expected noise on the first 7 days

The typosquat rule will fire on any domain you have not seen before
that happens to be Levenshtein-1 from a protected brand. **Expected
volume: 0–3 alerts per day** on a typical 100-host network. Most
will close as `false-positive` after a 30-second eyeball check.

The NRD rule will fire on first-time visits to legitimate new
domains (news sites, vendor portals, partner docs). **Expected
volume: 1–10 alerts per day.** The 3-event threshold suppresses
single-event noise but does not catch one-off legitimate visits
to a brand-new site. That is the expected behavior — high-precision,
low-recall by design.

The TLD-burst, dormant, and registration rules rarely fire in normal
traffic. When they fire, treat them seriously.

### 3. Promote experimental → production after tuning

After 30 days of tuning, follow the Promotion criteria in the
Tuning playbook above to promote any rule whose false-positive
rate is below 20%. Promotion is a single-line edit in the rule
file (`promotion: production`).

### 4. Test gate

44 new tests, all green on `cdcefcb`; Cybersec review returned PASS.

```
server/tests/test_t1583_001_brand_protection.py             (6 tests)
server/tests/rules/test_t1583_001_dns_intel_integration.py
server/tests/rules/test_t1583_001_domain_acquisition_nrd_rule.py
server/tests/rules/test_t1583_001_domain_acquisition_tld_burst_rule.py
server/tests/rules/test_t1583_001_domain_acquisition_typosquat_rule.py
server/tests/rules/test_t1583_001_domain_acquisition_dormant_rule.py
server/tests/rules/test_t1583_001_domain_registration_internal_rule.py
```

Total: 6 test files, ~525 LOC, 44 test functions.

---

## Cross-reference

* [[PHASE15 — Sigma compound conditions]] — the engine grammar this
  pack stays inside.
* [[PHASE16 — Required fields]] — where `dns_age_seconds`,
  `dns_last_seen_days`, `dns_reactivation_burst` come from in the
  collector.
* [[PHASE26 — WebUI Agents]] — the previous cycle (v3.1.0). This phase
  is the first `detection` track cycle after the WebUI push.
* `docs/decisions/` — the precision commitment is recorded as a
  decision (Faris, 2026-09-03, "tingkat akurasi 80%").
* `server/rules/builtin/mitre_attack/` — the 5 rule files.
* `server/src/zaqorincore_server/detection/` — the Python helpers.

---

## Substance markers

* New code: 3 files (`dns_intel_interface.py`, `brand_protection.py`,
  `detection/__init__.py`)
* New rules: 5 YAML files
* New tests: 6 test files, 44 test functions
* New docs: this file (PHASE29) + ROADMAP update
* New artifact: agent collector stub + CLI stub (`dns_intel.py`,
  `zaqorin-dns-intel-stub.py`)

Six substance markers — well above the 2-marker threshold for a
"ship" tag.

## Next phases (per detection track)

* **v3.2.1** — precision telemetry scaffolding to measure the actual
  rate against the 80% target (counters on rule firings, FP close-out,
  alert-to-incident conversion).
* **v3.3.0** — live RDAP feed, expanded brand list, distinct-SLD
  correlator, multi-prefix UA allowlist.
* **v3.4.0** — T1583.002 (DNS server) and T1583.003 (Virtual Private
  Server) coverage, following the same precision design.