# Self-defense detections

These rules protect the ZaqorinCore platform itself from attack. Every
other detection category assumes the server and agent are trustworthy;
self-defense closes that assumption by emitting alerts whenever the
platform's surface (HTTP, WebSocket, audit, WebUI, agent commands)
shows signs of being probed, attacked, or silently disabled.

## Why a separate track

A self-defence detection that fires during a hostile intrusion is the
last line of defence, not the first. If `/ws/agent` is being brute-forced
or the audit JSONL has been silently disabled, the rest of the
detection catalogue is operating on a compromised substrate. Treat
self-defense hits as **infrastructure emergencies**, not regular alerts.

## Rule catalogue

| ID | Title | MITRE | Severity | Mapped finding |
| --- | --- | --- | --- | --- |
| [T1190.001](T1190_001_ws_hello_oversized.md) | WS HELLO frame malformed or oversized | [T1190](https://attack.mitre.org/techniques/T1190/) | High | F-001 v3.2.1 |
| [T1110.003](T1110_003_ingest_bruteforce.md) | Ingest endpoint 401/403 burst from single IP | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | High | F-013 v3.2.1 |
| [T1078.001](T1078_001_api_key_geo_anomaly.md) | API key use from new src_ip or unusual hour | [T1078](https://attack.mitre.org/techniques/T1078/) | Medium | F-006 v3.2.1 |
| [T1098.001](T1098_001_audit_log_gap.md) | Audit log JSONL persistence silently disabled | [T1098](https://attack.mitre.org/techniques/T1098/) | High | F-008 v3.2.1 |
| [T1505.003](T1505_003_csp_violation.md) | WebUI CSP violation (blocked inline script or style) | [T1505](https://attack.mitre.org/techniques/T1505/) | Medium | F-007 / F-016 v3.2.1 |
| [T1505.004](T1505_004_csp_report_burst.md) | CSP report burst from single src_ip (rate-limit probe) | [T1505](https://attack.mitre.org/techniques/T1505/) | Medium | F-017 v3.4.2 |
| [T1499.004](T1499_004_ws_dos.md) | WS frame size or rate limit exceeded | [T1499.004](https://attack.mitre.org/techniques/T1499/004/) | High | F-009 v3.2.1 |
| [T1485.001](T1485_001_nft_invalid_table_chain.md) | nft binary called with non-whitelisted table/chain | [T1485](https://attack.mitre.org/techniques/T1485/) | High | F-4 v3.2.1 |
| [T1078.002](T1078_002_hmac_replay_multi_ip.md) | shared_secret HMAC auth from new src_ip | [T1078](https://attack.mitre.org/techniques/T1078/) | High | F-1 v3.2.1 |
| [T1190.002](T1190_002_hmac_challenge_bruteforce.md) | WS HMAC challenge failures burst from single src_ip | [T1190](https://attack.mitre.org/techniques/T1190/) | Medium | F-1 v3.2.1 |
| [T1059.004](T1059_004_curl_pipe_bash.md) | install.sh invoked via subprocess with piped input | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Medium | F-015 (deferred, closed in v3.4.1) |

## Shared tuning knobs

| Variable | Purpose | Default |
| --- | --- | --- |
| `ZAQORIN_SELF_DEFENSE_WHITELIST` | CIDR list applied by the runner (not the rule) to suppress false positives for known operator traffic. | unset (empty) |
| `ZAQORIN_SELF_DEFENSE_BUSINESS_HOURS` | Hour window used by the T1078.001 off-hours sub-signal. | `06:00-22:00` (local) |

## Lifecycle

Self-defense rules live under `server/rules/builtin/self_defense/` and
ship with the server. They are versioned alongside the platform; each
rule records its `date` and `modified` fields in YAML. Adding a new
rule means adding both the YAML and a documentation page here.