# Round 7 — CLEAN

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| Round        | 7                                                           |
| Cycle        | 68                                                          |
| Phase        | 1 (TEST track, NARROW SCOPE)                                |
| Date         | 2026-09-03                                                  |
| Commit under audit | `1ae1542` (v3.4.10)                                    |
| Scope        | Entire `server/src/zaqorincore_server/` tree                |
| Question     | Are there any other F-021-style `startswith` / `endswith`    |
|              | IP-prefix bugs where `ipaddress.ip_address()` /             |
|              | `ipaddress.ip_network()` should be used?                    |
| Result       | **CLEAN — 0 findings**                                      |

## Searches performed

| # | Pattern                                                                                  | Hits |
|---|------------------------------------------------------------------------------------------|------|
| 1 | `startswith(("10."` / `startswith("10.")` / `startswith("192.168.")` / `startswith("172.")` | 0    |
| 2 | `startswith("\d{1,3}\.` (any IP-octet prefix)                                            | 0    |
| 3 | `endswith("…")` where suffix is an octet / IP fragment                                    | 0    |
| 4 | `ipaddress` module imports                                                               | 5 (2 `.pyc`) |
| 5 | `ip_address` / `ip_network` / `is_loopback` / `is_private` / `is_link_local` callsites    | 42   |
| 6 | `RFC1918` / `rfc1918` / `private.*ip` / `internal.*ip` references                          | 35   |

All matches in (4)–(6) are **correct uses** of the `ipaddress` module
(parsed IP, not string-prefix). Specifically:

- `api/v1/agents_provision.py:725` — F-021 fix already shipped
  (`ipaddress.ip_address(host)` + `addr.is_private / .is_loopback / .is_link_local / .is_multicast / .is_reserved`).
- `soar/backends/generic_webhook.py:88–101` — `_SSRF_BLOCKED_NETWORKS` list
  built from `ipaddress.ip_network(...)` calls; host is parsed with
  `ipaddress.ip_address(host)` at line 153; resolution helper
  `_is_blocked_address` at line 118. No string-prefix.

## Every `startswith` callsite in scope (not exhaustive — full list)

| File                                                | Purpose                                                        | IP-related? |
|-----------------------------------------------------|----------------------------------------------------------------|-------------|
| `api/v1/audit_bots.py:332`                          | Comment-line filter (`#`)                                       | No          |
| `api/v1/agents_provision.py:308`                    | Bracketed-IPv6 detection (`[` / `]`)                            | No (brackets, not octets) |
| `action_kinds.py:305`                               | Path-absolute check (`/`)                                       | No          |
| `soar/backends/jira.py:111`                         | URL scheme (`https://`)                                         | No          |
| `soar/backends/discord.py:70`                       | URL scheme + vendor host (`https://discord.com/api/webhooks/`)  | No          |
| `soar/backends/thehive.py:73`                       | URL scheme (`http(s)://`)                                       | No          |
| `soar/backends/generic_webhook.py:236`              | URL scheme (`http(s)://`)                                       | No          |
| `soar/backends/slack.py:94`                         | URL scheme + vendor host (`https://hooks.slack.com/`)          | No          |
| `security.py:76`                                    | Content-Type sniff (`text/html`)                                | No          |
| `rule_engine/sigma.py:105,109`                      | Sigma rule modifier prefixes (`re:`, `contains:`)               | No          |
| `evidence.py:160`                                   | Hidden-file blocklist (`.`)                                     | No          |

None of the above classify an IP — all are URL-scheme / content-type /
file-name / rule-modifier prefix checks, which is what `startswith` is
for.

## Conclusion

The Round 6 fix (commit `1ae1542`, F-021) was the **last** place in
the server tree where a `startswith` was being used to classify IPs.
No other F-021-style prefix-overlap bugs exist. Round 7 is CLEAN.

## Files touched this round

- `docs/security/findings/ROUND7-CLEAN.md` (new — this file)
- `docs/security/AUDIT-2026-09-03.md` (Round 7 section appended)
