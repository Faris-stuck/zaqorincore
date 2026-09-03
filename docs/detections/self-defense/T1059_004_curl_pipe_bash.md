# T1059.004 — install.sh or update.sh invoked via subprocess with piped input

**MITRE**: [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
**Sub-technique**: [T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
**Severity**: Medium
**Status**: Experimental
**Mapped finding**: [F-015 (deferred, closed in v3.4.1)](../../security/findings/F-015-install-command-curl-pipe-bash.md)

## Summary

Detects the classic `curl | bash` / `wget | sh` install pattern at
runtime. The agent audit layer records the `cmdline` of every
subprocess it spawns; when the `cmdline` matches a remote-fetch piped
into a shell interpreter, this rule fires.

The deferred status reflects that the safe long-term remediation is
signed package delivery; the rule exists so that the audit trail is
searchable and operators can see when an installer fetch pattern ran.
False positives are expected in CI runners and dev workstations that
legitimately use `curl | bash` to bootstrap tooling, which is why the
rule is medium severity.

## Detection logic

```yaml
logsource:
  product: zaqorincore
  service: agent
detection:
  selection:
    event_type: process.exec
  filter_curl_pipe:
    cmdline: 're:curl[^\n]*\|\s*(bash|sh)'
  filter_wget_pipe:
    cmdline: 're:wget[^\n]*\|\s*(bash|sh)'
  condition: selection and (filter_curl_pipe or filter_wget_pipe)
fields:
  - src_ip
  - agent_id
  - cmdline
level: medium
```

## Sample event

```json
{
  "event_type": "process.exec",
  "src_ip": "198.51.100.10",
  "agent_id": "agent-build-02",
  "cmdline": "curl -fsSL https://get.example.com/install.sh | bash",
  "ts": "2026-09-04T07:02:33Z"
}
```

## Tuning

- **Whitelist**: `ZAQORIN_SELF_DEFENSE_WHITELIST` (CIDR list) for CI
  runner networks where this pattern is expected.
- **Threshold**: Single observation. Tune by widening the regex only if
  your fleet uses uncommon fetchers.
- **Known false positives**:
  - Developer running install scripts during local development.
  - CI runner bootstrapping a build image.
  - Upstream vendor install instructions using the pattern.

## References

- https://attack.mitre.org/techniques/T1059/004/
- https://github.com/Faris-stuck/zaqorincore/security/advisories
- [F-015 finding](../../security/findings/F-015-install-command-curl-pipe-bash.md)