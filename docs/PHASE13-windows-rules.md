# PHASE13 — Windows Detection Rules (Sigma v1.4.0)

Status: **Shipped** in v1.4.0 (commit pending)
Owner: Detection Engineering
Reviewers: Code Review, Cyber Security

## 1. Why this slice exists

v1.2.0 shipped the **Windows Event Log collector** (6 event IDs
subscribed: 4624/4625/4688/4698/4720/4732) and the **Windows
action applier** (4 action kinds: taskkill/icacls/netsh/klist).
What was missing: **detection rules** that turn those events
into alerts.

Without rules, the Windows collector produces a firehose of
events that nobody reads. With rules, the same firehose becomes:

- 1 alert per real brute-force attempt
- 1 alert per privilege escalation
- 1 alert per LSASS credential dump
- 1 alert per LOLBin-spawned process
- 1 alert per new user account

The rules live in `server/rules/builtin/windows_eventlog/` and
run on the same SigmaRuleRunner that already powers the 52
Linux/macOS/EDR rules. The runner is GOOS-agnostic; the rules
just declare the event source as `windows.security.<EventID>`.

## 2. The 5 rules shipped in v1.4.0

| Rule ID | ATT&CK | Event ID | Level | Threshold | Action |
|---|---|---|---|---|---|
| `builtin-windows-4625-brute-force` | T1110 | 4625 | high | 10 in 60s | `block_ip` (1h) |
| `builtin-windows-4688-suspicious-parent` | T1218 | 4688 | high | 1 event | `snapshot_processes` |
| `builtin-windows-lsass-read` | T1003.001 | 4663 | critical | 1 event | `snapshot_processes` |
| `builtin-windows-4732-priv-group-add` | T1098 | 4732 | critical | 1 event | `snapshot_processes` |
| `builtin-windows-4720-account-create` | T1136 | 4720 | medium | 1 event | `snapshot_processes` |

### 2.1 T1110 — Windows failed logon burst (brute force)

```
window: 60 s
count:  10
match:  source == "windows.security.4625"
        (no account-name filter — attacker rotates usernames)
action: block_ip target={{ip_address}} ttl_sec=3600
dedup:  {{ip_address}} (one alert per source IP, per 30-minute cooldown)
```

The Windows analog of the Linux `ssh_bruteforce` rule that
ships in v0.3.0. The `block_ip` action maps to
`netsh advfirewall firewall add rule name="ZaqorinBlock_<ip>"
dir=in action=block remoteip=<ip>` on Windows (see
`agent/internal/response/kinds/windows_kinds_windows.go`,
shipped in v1.2.0).

### 2.2 T1218 — LOLBin parent process

```
match:  source == "windows.security.4688"
        parent_process_name ∈ {regsvr32, mshta, wscript, cscript,
                               certutil, bitsadmin}
action: snapshot_processes target={{pid}}
dedup:  {{pid}}:{{parent_process_name}}
```

The minimum-viable LOLBin set — the six binaries that appear
most often in public LOLBins-project reports for initial access
and post-exploitation. The full list of 100+ binaries is a
v1.4.x follow-up.

### 2.3 T1003.001 — LSASS handle open

```
match:  source == "windows.security.4663"
        target_filename contains "lsass.exe"
action: snapshot_processes target={{pid}}
dedup:  {{pid}}:{{target_filename}}
```

The Windows analog of the Linux `T1003_credential_dump` rule
that detects `/proc/*/mem` opens targeting lsass. The 4663
event is produced by the **kernel audit subsystem**, not by
the default eventlog subscription. Operators must enable
"Audit Handle to Kernel Objects" via Group Policy:

```
Computer Configuration
  → Policies
    → Windows Settings
      → Security Settings
        → Advanced Audit Policy Configuration
          → Object Access
            → Audit Handle to Kernel Objects (Success)
```

Without this GPO, the rule never fires. The PHASE12-windows.md
guide documents the full GPO set.

### 2.4 T1098 — User added to privileged group

```
match:  source == "windows.security.4732"
        target_sid ∈ {BUILTIN\Administrators, Domain Admins,
                      Enterprise Admins, Schema Admins}
action: snapshot_processes target={{pid}}
dedup:  {{target_sid}}:{{member_sid}}
```

Four target SIDs. A member added to any of them is either a
misconfiguration (worth surfacing) or a privilege-escalation
attack (worth alerting on). The SIDs in the rule are
`EXAMPLE-S-1-5-32-{544,548,549,551}` — operators with a real
Active Directory should override with the
`S-1-5-32-{544,548,549,551}` form by copying the rule to
`rules.local_overrides/windows_eventlog/`.

### 2.5 T1136 — User account created

```
match:  source == "windows.security.4720"
action: snapshot_processes target={{pid}}
dedup:  {{target_user_name}} (1-hour cooldown per new account)
```

Every new account is a potential persistence mechanism. The
1-hour cooldown per (host, target_user_name) means a real
onboarding flow that creates N accounts in N hours produces
N alerts, not one storm.

**Known limitation:** the Sigma engine does not yet parse
`condition: selection and not filter_business_hours`, so this
rule fires on every 4720 (24x7) instead of off-hours only.
Operators who want a stricter rule can override the rule
in `rules.local_overrides/windows_eventlog/` and add an
explicit `parent_process_name` allowlist (e.g.
`svchost.exe`, `powershell.exe` from a known provisioning
script). The off-hours filter is tracked as a v1.4.x
follow-up in ROADMAP.

## 3. Why these 5 (and not the other 10 in the ROADMAP)

The ROADMAP listed "10-20 new platform-specific rules" as a
v1.2.0 prerequisite. v1.2.0 shipped zero because:

- The eventlog_common.go decoder landed in v1.0.0 but the
  rule runner was already feature-locked to plain string /
  list / `re:` / `contains:` matches (no `|startswith`,
  `|endswith`, `|ge`, `|lt` modifiers).
- A rule like "PowerShell EncodedCommand" needs
  `|startswith` or `|contains` to fire correctly. The
  engine supports `contains:` but only as a prefix
  (e.g. `contains:EncodedCommand`), not as a substring
  against the full command line.

Rather than wait for a rule-engine upgrade, v1.4.0 ships
**5 rules that work today** with the existing engine. The
remaining 5-10 rules are queued for the engine upgrade
(ROADMAP item "v1.4.x — Sigma engine modifier support").

## 4. Mapping summary

```
Sigma rule           ATT&CK     PCI DSS   ISO 27001   NIST 800-53
─────────────────────────────────────────────────────────────────
4625 brute force     T1110      10.2.4    A.5.16      AC-7
4688 LOLBin parent   T1218      10.2.1    A.5.7       AU-2
4663 LSASS read      T1003.001  8.2.3     A.8.5       IA-5
4732 priv group add  T1098      7.1       A.5.15      AC-6
4720 account create  T1136      8.1.4     A.5.16      AC-2
```

The compliance mapping is in each rule's `tags:` block as
well, so the Phase 6 compliance scanner (shipped in v0.8.0)
automatically counts these rules toward the relevant
framework's coverage.

## 5. Testing

The 5 rules have 15 tests in
`server/tests/test_windows_eventlog_rules.py` (3 per rule
+ 1 loader sanity test). All 15 pass on Linux with no
Windows runtime; the runner's selection logic is
GOOS-agnostic.

```
$ pytest tests/test_windows_eventlog_rules.py
...............                     [100%]
15 passed in 0.32s

$ pytest  # full server suite
250 passed in 19.74s
```

The full server suite went from 235 → 250 with v1.4.0. The
+15 delta is the new test file. No existing tests were
modified.

## 6. Operator rollout

1. Pull v1.4.0
2. The 5 rules auto-load (the rule runner picks up
   everything under `server/rules/builtin/`)
3. On Windows hosts running the v1.2.0 agent, enable the
   GPO set documented in `docs/PHASE12-windows.md`:
   - Audit Handle to Kernel Objects (Success) — for T1003
   - Include command line in process creation events — for
     T1218
4. Verify by:
   - Looking for `rule_id=builtin-windows-4688-suspicious-parent`
     in the alerts UI after running `mshta.exe` once
   - Forcing 10 failed logons in 60s and confirming
     `block_ip` action was issued (check
     `netsh advfirewall firewall show rule name=ZaqorinBlock_*`)

## 7. Deferred (v1.4.x follow-up)

- PowerShell EncodedCommand (needs `|contains` substring
  modifier, not just prefix)
- PowerShell DownloadString (same as above)
- Scheduled Task Created (4698) — already in the eventlog
  subscription, needs the rule
- User account deleted (4726) — pair with T1136 for
  lifecycle completeness
- WMI event subscription persistence (event ID 5861) —
  needs WMI provider, not the default eventlog subscription
- off-hours filter for T1136 (needs `condition: selection
  and not filter` parsing)
- Sigma engine `|startswith`, `|endswith`, `|ge`, `|lt`
  modifier support (unlocks the 10+ remaining Windows
  rules from the ROADMAP)

## 8. Honest gap

The 5 rules were tested on Linux with a fake-redis runner.
The selection logic, dedup, cooldown, count-in-window, and
action-rendering paths are all exercised by the 15 tests.
What was NOT exercised:

- Real Windows Event Log events flowing through the
  eventlog_common.go decoder into the metadata schema the
  rules expect
- Real `netsh advfirewall` block_ip action on a real
  Windows host
- Real GPO rollout on a real AD domain

The rule-engine path is the same code path the Linux rules
use in production, so the gap is in the upstream decoder +
downstream action applier, both of which were tested in
v1.2.0 (decoder on Linux, action applier via cross-compile
smoke test only — see `docs/PHASE12-windows.md`).

Operators MUST run a real-Windows integration smoke test
after upgrading to v1.4.0:

```powershell
# 1. Force a brute-force
for ($i=0; $i -lt 10; $i++) { runas /user:nope /netonly bad 2>$null }

# 2. Look for the alert in the UI
# 3. Confirm the block_ip rule was added
netsh advfirewall firewall show rule name=ZaqorinBlock_*
```
