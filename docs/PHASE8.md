# Phase 8 — Compliance Pack (50+ rules)

**Status:** shipped as v0.8.0 (2026-08-28).

## Goal

Make ZaqorinCore ready for regulated environments. Auditors want to
see how the detection library maps to the controls they enforce.
This phase adds four out-of-the-box compliance packs that cover the
most common security frameworks in Indonesia and abroad.

## Rule packs shipped (51 rules total, plus 5 baseline = 56)

### `iso27001_nist80053/` (13 rules)

Maps detection coverage to **ISO/IEC 27001:2022 Annex A** and the
matching **NIST SP 800-53** families. Each rule names the
specific control it implements (`A5.15`, `A5.16`, …).

| Rule ID                                | ISO 27001 control | NIST 800-53 | Description                                      |
|----------------------------------------|-------------------|-------------|--------------------------------------------------|
| A5_15_access_control_unauthorized      | A.5.15            | AC-2        | Privileged access without entitlement            |
| A5_16_identity_management_disable     | A.5.16            | AC-2(2)     | Disabled-account login attempt                   |
| A5_17_authentication_info_disclosure  | A.5.17            | IA-5        | Auth info exposed in logs (password in URI)      |
| A5_18_access_rights_unauthorized      | A.5.18            | AC-6        | Privilege escalation to root/SYSTEM              |
| A5_24_incident_management_log_tamper  | A.5.24            | AU-9        | Audit log deletion / truncation                  |
| A5_25_evaluation_security_events      | A.5.25            | SI-4        | Security event review failure                    |
| A5_28_collection_evidence             | A.5.28            | AU-12       | Evidence collection gap (no chain-of-custody)    |
| A5_30_ict_readiness_bcp               | A.5.30            | CP-2        | Business continuity / DRP test missed            |
| A5_31_legal_preservation              | A.5.31            | AU-11       | Records destroyed before retention expiry        |
| A5_34_privacy_protection              | A.5.34            | SI-12       | PII handling in violation of data classification |
| A5_36_compliance_policy_violation     | A.5.36            | CA-7        | Compliance policy exception (drift)              |
| A8_15_logging_detect_tamper           | A.8.15            | AU-9        | Log integrity check failure                      |
| A8_5_secure_authentication_mfa_bypass | A.8.5             | IA-2(1)     | MFA bypass on privileged account                 |

### `pci_dss/` (13 rules)

Maps to **PCI DSS v4.0** requirements 1–12. Each rule names
the requirement it supports.

### `uu_pdp/` (13 rules)

Maps to the **Indonesia UU PDP No. 27/2022** (Personal Data
Protection) and the related **POJK/BI** sectoral regulations.
Rules are in Bahasa Indonesia.

### `mitre_attack/` (12 rules)

Maps to **MITRE ATT&CK Enterprise** techniques. These are
the technique-level detections SOC analysts expect: brute
force, credential dump, command interpreter abuse, data
encrypted for impact, etc.

## Reference format

Every rule has a `tags` list with at least one framework
identifier and a `references` list with at least one
URL or document citation. Auditors can use the references
to cross-check the rule against the standard.

```yaml
title: A5.16 disabled account login attempt
id: iso27001-A5-16
level: high
description: |
  Detects authentication attempts against disabled accounts.
tags:
  - compliance.iso27001.A5.16
  - compliance.nist80053.AC-2(2)
references:
  - https://www.iso.org/standard/27001
  - https://csrc.nist.gov/projects/sp800-53
detection:
  selection:
    event_type: "auth_login"
  condition: selection
action:
  kind: evidence_capture
  target: "{{host_id}}"
  ttl_sec: 3600
```

## How the runner picks them up

`rules/builtin/` is scanned recursively by `SigmaRuleRunner`.
A rule dropped into any subdirectory is loaded automatically
— no manifest update needed. Rule files must have `id`,
`title`, `level`, `detection`, and at least one of `tags` or
`references`.

The runner enforces the same shape on every file:

* `id` must be unique across the whole `rules/` tree (test: `test_builtin_packs_have_unique_ids`).
* Every rule must have a `tags` list (test: `test_builtin_packs_have_tags`).
* Every rule must have a `references` list (test: `test_builtin_packs_have_references`).

These tests fail CI on a regression — you can't ship a
compliance pack without citations.

## Evidence locker key rotation (server)

The `EvidenceStore` now supports key rotation. The signing
key has an id (`current` by default); rotating generates a
new key and keeps the old one in history. Old evidence
still verifies because the old key is retained.

```python
store = EvidenceStore(base_dir="/var/lib/zaqorincore/evidence")
store.submit(payload_1)
new_id = store.rotate()          # creates key + previous slot
store.submit(payload_2)
assert store.verify("alert-1")    # still verifies
assert store.verify("alert-2")    # also verifies
```

Operators can rotate the signing key on a schedule (e.g.
quarterly) without losing the ability to verify older
evidence. If a key is compromised, it can be wiped from
`store.keys` and all evidence signed with it will fail
verification — the chain-of-custody is preserved.

## Tests added

| Test                                       | Asserts                                     |
|--------------------------------------------|---------------------------------------------|
| `test_compliance_packs_load[iso27001_10]`  | at least 10 ISO rules load                  |
| `test_compliance_packs_load[pci_dss_10]`   | at least 10 PCI rules load                  |
| `test_compliance_packs_load[uu_pdp_10]`    | at least 10 UU PDP rules load               |
| `test_compliance_packs_load[mitre_attack_8]` | at least 8 MITRE ATT&CK rules load        |
| `test_builtin_packs_have_unique_ids`       | no two rules share an id                    |
| `test_builtin_packs_have_tags`             | every rule has a `tags` list                |
| `test_builtin_packs_have_references`       | every rule has a `references` list          |
| `test_evidence_rotation.py::test_rotate_changes_active_key` | rotate replaces current + keeps old |
| `test_evidence_rotation.py::test_evidence_verifies_across_rotation` | old + new both verify after rotate |
| `test_evidence_rotation.py::test_sidecar_records_key_id` | sidecar names the key that signed it |
| `test_evidence_rotation.py::test_verify_fails_for_evidence_signed_with_unknown_key` | wiped key → evidence fails |

## Metrics

* Compliance rules shipped: **51** (target was 50+).
* Total rules in `rules/builtin/`: **56** (51 compliance + 5 baseline).
* Go canary kinds now: 4 (file, tcp_socket, http_endpoint, credential).
* Server test count: **164** (was 152 at v0.7.0).
* Go test packages: 10 (still all green).
