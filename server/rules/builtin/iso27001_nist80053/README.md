# ISO 27001:2022 / NIST SP 800-53 Compliance Rules

Built-in Sigma-style detection rules that map host activity to ISO 27001:2022
Annex A controls and NIST SP 800-53 Rev 5 control families. Each rule produces
one or more alerts when its detection window fires, so an operator can prove
the relevant control is being monitored.

## Rule inventory

| File | Title | ISO 27001 | NIST 800-53 | Level |
|------|-------|-----------|-------------|-------|
| `A5_15_access_control_unauthorized.yml` | Multiple failed authentication attempts from one source | A.5.15 | AC-7 | high |
| `A5_16_identity_management_disable_account.yml` | Authentication attempt for disabled or deleted account | A.5.16 | AC-2(2) | high |
| `A5_17_authentication_info_disclosure.yml` | Authentication log permissions weakened | A.5.17 | AC-9 | high |
| `A5_18_access_rights_unauthorized_change.yml` | Sensitive file made world-writable | A.5.18 | AC-3 | high |
| `A5_24_incident_management_log_tamper.yml` | Log truncation or clearing | A.5.24 | AU-9 | critical |
| `A5_25_evaluation_security_events.yml` | Audit daemon stopped | A.5.25 | AU-2 | critical |
| `A5_28_collection_evidence.yml` | Evidence capture action triggered | A.5.28 | AU-12 | high |
| `A5_30_ict_readiness_bcp.yml` | Backup process failure | A.5.30 | CP-9 | high |
| `A5_31_legal_preservation.yml` | Mass file deletion by privileged account | A.5.31 | SI-12 | critical |
| `A5_34_privacy_protection.yml` | Bulk access to PII directory | A.5.34 | SI-12.1 | high |
| `A5_36_compliance_policy_violation.yml` | Unauthorized service started | A.5.36 | CM-7 | medium |
| `A8_5_secure_authentication_mfa_bypass.yml` | Multi-factor authentication disabled for account | A.8.5 | IA-2(1) | critical |
| `A8_15_logging_detect_tamper.yml` | Syslog forwarding broken | A.8.15 | AU-3 | high |

## How to extend

1. Pick the next control that needs coverage.
2. Copy an existing rule that targets the same `event_type`.
3. Update the title, description, references, tags, and the selection
   (or regex in `command`) to match the behaviour you want to alert on.
4. Keep the file under 25 lines and re-run the validation command in
   `server/rules/builtin/iso27001_nist80053/`.

## Validation

```bash
cd server
python -c "import yaml, glob; [print(f, len(yaml.safe_load(open(f))['detection']['selection'])) for f in sorted(glob.glob('rules/builtin/iso27001_nist80053/*.yml'))]"
```
