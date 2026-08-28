# PCI DSS v4.0 Detection Rules

This directory contains Sigma-style detection rules that map to specific
PCI DSS v4.0 requirements. Each rule targets a single control objective
and is intended to be reviewed as part of quarterly PCI compliance evidence.

| File | PCI DSS Requirement | Description |
|------|---------------------|-------------|
| `req1_firewall_unauthorized_rule.yml` | 1.2.1 | Firewall rule added by non-root user |
| `req2_default_credential_use.yml` | 2.2.2 | Login with default vendor account |
| `req3_cardholder_data_unencrypted.yml` | 3.5.1 | Access to cleartext PAN field |
| `req4_encryption_disabled.yml` | 4.2.1 | TLS handshake fails or uses weak cipher |
| `req5_antimalware_disabled.yml` | 5.2.4 | Antimalware daemon stopped |
| `req6_critical_patch_missing.yml` | 6.3.3 | Known-vulnerable package running |
| `req7_access_control_business_need.yml` | 7.2.4 | Privileged access without change ticket |
| `req8_user_identification_shared.yml` | 8.2.1 | Same user from 2+ IPs in 5 minutes |
| `req9_physical_media_unauthorized.yml` | 9.4.1 | USB storage mounted on a server |
| `req10_audit_log_disabled.yml` | 10.2.1 | Audit daemon stopped |
| `req11_vuln_scan_missed.yml` | 11.3.1 | Scheduled vulnerability scan missed |
| `req12_security_policy_violation.yml` | 12.2.1 | Known-bad binary executed |
| `appendix_c_payment_app_anomaly.yml` | Appendix C | Payment service restart outside window |

## Schema

Each YAML file contains the fields required by the Zaqor rules loader:

- `title`, `id` (UUID4 lowercase), `description`, `author`, `date`, `modified`
- `references` (list of URLs)
- `tags` (list, includes a `pci_dss.<requirement>` tag for grouping)
- `level` (informational, low, medium, high, critical)
- `detection.selection`, `detection.condition`, `detection.timeframe`
- `cooldown_sec`, `dedup_key` (loader fields, same as `ssh_bruteforce.yml`)

Regex modifiers (`|re`, `|contains`, `|startswith`, `|ne`) follow the
project's standard syntax. Regex values that contain backslashes are
single-quoted to avoid PyYAML 1.1 escape interpretation.

## Validation

```python
import yaml, glob
files = sorted(glob.glob('rules/builtin/pci_dss/*.yml'))
for f in files:
    with open(f) as fh:
        data = yaml.safe_load(fh)
    assert 'detection' in data
    assert 'selection' in data['detection']
print(f"All {len(files)} rules parse OK")
```
