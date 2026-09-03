## [3.2.0] - 2026-09-03 — T1583.001 Domain Acquisition Detection Pack

v3.2.0 adds detection coverage for **MITRE ATT&CK T1583.001 — Acquire
Infrastructure: Domains** with five precision-engineered Sigma rules
and a Levenshtein-based typosquat engine. Coverage rises from 16/200
(8.0%) to **17/200 (8.5%)**.

Per the precision commitment (Faris, 2026-09-03, "tingkat akurasi 80%"):
every rule in this pack applies four precision techniques:

1. **Multi-signal correlation** — rules require at least two signals
   to match within a defined window. Single-pattern matches are
   suppressed.
2. **Explicit thresholds** — minimum evidence count (count + timeframe
   pairs in each rule) before the rule fires.
3. **Whitelist** — `filter_legit` / `filter_legit_brand` /
   `filter_known_ua` blocks exclude known-good traffic (captive portals,
   CDN edge, brand-owners themselves, monitoring user-agents).
4. **Experimental promotion tier** — all rules ship at
   `promotion: experimental`. Production teams should tune the
   thresholds per environment.

Measurement of the actual precision rate is deferred to post-production
telemetry (see `docs/PHASE29-dns-intel-detection.md` for the tuning
playbook). The design commitment here is **80%+ precision**, but the
real number will be observed, not asserted.

### Added

- **Sigma rules** in `server/rules/builtin/mitre_attack/` (cycle 49,
  `detection` track):
  - `T1583_001_domain_acquisition_nrd.yml` — Newly Registered Domain
    queried by an internal host within 5 minutes of registration.
  - `T1583_001_domain_acquisition_tld_burst.yml` — Burst (>= 5 unique)
    of queries to suspicious TLDs (.xyz, .top, .tk, .ml, .cf, .ga)
    from a single host in 60 seconds.
  - `T1583_001_domain_acquisition_typosquat.yml` — Levenshtein
    distance 1-2 from a protected brand (komatsu.co.id, microsoft.com,
    google.com by default; configurable via
    `ZAQORIN_PROTECTED_BRANDS`).
  - `T1583_001_domain_acquisition_dormant.yml` — Previously dormant
    domain (> 90 days since last seen) receives a burst of >= 10
    queries in 24 hours.
  - `T1583_001_domain_registration_internal.yml` — Internal host POST
    to a domain registrar endpoint (namecheap / porkbun / cloudflare)
    with an unknown user-agent.
- **Python helpers** in `server/src/zaqorincore_server/detection/`:
  - `dns_intel_interface.py` — Protocol class + concrete `WHOISRDAPClient`
    stub (RDAP/WHOIS feed integration deferred to v3.3.0+).
  - `brand_protection.py` — Levenshtein implementation + protected-brand
    list + `check_typosquat` helper used by the Sigma rule matcher.
- **Agent collector stub** at `agent/collectors/dns_intel.py` and
  `agent/cmd/zaqorin-dns-intel-stub.py` — interface only; live RDAP
  feed wiring is a v3.3.0 deliverable.
- **44 new tests** (38 Sigma rule tests + 6 brand protection tests +
  integration flow):
  - `server/tests/rules/test_t1583_001_domain_acquisition_nrd_rule.py`
  - `server/tests/rules/test_t1583_001_domain_acquisition_tld_burst_rule.py`
  - `server/tests/rules/test_t1583_001_domain_acquisition_typosquat_rule.py`
  - `server/tests/rules/test_t1583_001_domain_acquisition_dormant_rule.py`
  - `server/tests/rules/test_t1583_001_domain_registration_internal_rule.py`
  - `server/tests/rules/test_t1583_001_dns_intel_integration.py`
  - `server/tests/test_t1583_001_brand_protection.py`
- **Environment variables** in `server/.env.example`:
  - `ZAQORIN_WHOIS_RDAP_URL` — RDAP endpoint (empty = disabled).
  - `ZAQORIN_PROTECTED_BRANDS` — comma-separated brand list.

### Changed

- Bumped version `3.1.0` -> `3.2.0` in `server/pyproject.toml`.
- Detection streak now extends to **cycle 49** (6 consecutive cycles
  on the `detection` track, longest in ZaqorinCore history).

### Detection coverage

| MITRE technique        | Status   |
|------------------------|----------|
| T1583.001 Acquire Infra: Domains | **NEW** (5 rules) |

Overall coverage: **17/200 (8.5%)** MITRE ATT&CK techniques detected.

## [3.1.0] - 2026-09-02 — WebUI Agents: Zero-Terminal Onboarding