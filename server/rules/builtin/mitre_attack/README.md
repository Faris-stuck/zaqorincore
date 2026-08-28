# MITRE ATT&CK + NIST CSF 2.0 Coverage

Twelve Sigma rules mapping core ATT&CK enterprise techniques to NIST CSF 2.0 functions.
Use `mitre_attack_navigator.json` to import the coverage layer into the
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## Coverage Map

| Rule file | ATT&CK Technique | NIST CSF 2.0 | Tactic | Level |
|-----------|------------------|--------------|--------|-------|
| T1003_credential_dump.yml          | T1003 (OS Credential Dumping)            | DE.CM  | Credential Access | critical |
| T1059_command_interpreter.yml      | T1059 (Command and Scripting Interpreter)| DE.AE  | Execution         | high     |
| T1078_valid_accounts.yml           | T1078 (Valid Accounts)                   | PR.AC  | Initial Access    | high     |
| T1110_brute_force.yml              | T1110 (Brute Force)                      | DE.CM  | Credential Access | high     |
| T1190_exploit_public_app.yml       | T1190 (Exploit Public-Facing Application)| PR.PS  | Initial Access    | high     |
| T1486_data_encrypted_for_impact.yml| T1486 (Data Encrypted for Impact)        | RS.RP  | Impact            | critical |
| T1490_inhibit_recovery.yml         | T1490 (Inhibit System Recovery)          | RP.RP  | Impact            | critical |
| T1543_persistence_service.yml      | T1543 (Create or Modify System Process)  | DE.CM  | Persistence       | high     |
| T1547_boot_autostart.yml           | T1547 (Boot or Logon Autostart Execution) | DE.CM | Persistence       | high     |
| T1552_unsecured_credentials.yml    | T1552 (Unsecured Credentials)            | PR.DS  | Credential Access | high     |
| T1567_exfiltration_over_web.yml    | T1567 (Exfiltration Over Web Service)    | DE.AE  | Exfiltration      | high     |
| T1569_system_services_exec.yml     | T1569 (System Services: Service Execution) | DE.CM | Execution      | high     |

## NIST CSF 2.0 Function Legend

- **PR.AC** - Identity Management, Authentication, and Access Control (Protect)
- **PR.PS** - Platform Security (Protect)
- **PR.DS** - Data Security (Protect)
- **DE.CM** - Continuous Monitoring (Detect)
- **DE.AE** - Anomalies and Events (Detect)
- **RS.RP** - Response Planning (Respond)
- **RP.RP** - Recovery Planning (Recover)

## Importing the Navigator Layer

1. Open https://mitre-attack.github.io/attack-navigator/
2. Click **Open Existing Layer** -> **Upload from local**
3. Select `mitre_attack_navigator.json`
4. The 12 techniques will show in green (score = 1)
