# Web telemetry operator guide

This guide explains how to point ZaqorinCore at your web
server so the agent can detect attacks against your public
HTTP endpoints.

## What you get

When configured, the agent reads your web access logs and
forwards structured events to the server. The server runs
the existing Sigma engine and generates alerts for the
following detections out of the box:

- **T1190 exploit pattern** — known scanner user agents
  (`sqlmap`, `nikto`, `nmap`, `masscan`, `gobuster`,
  `nessus`, `wpscan`, `dirbuster`).
- **T1190 SQLi/XSS/path-traversal in URI** — keyword
  detection (`union select`, `<script>`, `../`, encoded
  variants).
- **T1110 HTTP brute force** — 10 failed (401/403) responses
  from one source IP in 60 seconds.
- **T1190 HTTP method anomaly** — TRACE, DEBUG, PROPFIND,
  etc. used against a public listener.

All alerts are subject to the standard chain-of-custody and
auto-response (block_ip, evidence capture) just like host
alerts.

## What you need

- nginx 1.10+ with the default `combined` access log format.
  If you have a custom `log_format`, change it to `combined`
  for the access log you want watched, or add a new
  `access_log` directive that uses `combined` and point
  ZaqorinCore at that file.
- (Optional) ModSecurity v3 with the OWASP Core Rule Set for
  full attack coverage. The agent reads ModSecurity audit
  logs the same way it reads nginx access logs.

## Configuration

Add a `log_sources` entry to your agent config (`agent.yaml`):

```yaml
log_sources:
  - name: nginx_access
    type: file
    path: /var/log/nginx/access.log
    read_from: end
  - name: modsec_audit
    type: file
    path: /var/log/modsecurity/audit.log
    read_from: end
```

The `name` field is what the agent stamps on each event as
the `source`. The reserved names are `nginx_access`,
`nginx_error`, and `modsec_audit` — using anything else
means the agent will forward the raw line but the server will
not know which parser to apply.

## ModSecurity audit log setup

ModSecurity audit logs are large and multi-line. The agent
treats each line as a separate event (section marker, header,
value). To keep the agent log volume manageable:

- Use ModSecurity's `SecAuditLogFormat Native` and set
  `SecAuditLogParts` to include only what you need. The
  default `ABCFHZ` is fine.
- Pipe audit logs to a separate file (not stderr) so other
  tools can ingest them.
- Rotate the audit log file daily with a tool like
  `logrotate(8)`. ZaqorinCore handles rotation gracefully
  (it re-opens the file when the inode changes).

## Limitations

- The agent reads what nginx writes. If your access logs are
  truncated, dropped, or behind a buffering proxy, the agent
  sees nothing. Use a FIFO or a direct file write to avoid
  the buffering proxy.
- Custom `log_format` directives are not supported. If you
  use a custom format, either switch to `combined` or
  extend `pkg/webtail/webtail.go` with a new branch in
  `ParseNginxLine`.
- TLS inspection is not done by the agent. Encrypted payload
  content is invisible — ModSecurity running as part of
  nginx is the right place to inspect TLS.
- Rate limiting is per-agent, not cluster-wide. A distributed
  attacker hitting your web app from many IPs in parallel
  may stay under the per-IP threshold. The server's Sigma
  engine can correlate across agents in a future release.

## Verifying it works

After configuring, restart the agent. Then make a test
request:

```bash
# 1. Tag yourself
curl -A "sqlmap/1.0" http://your-server/admin
# 2. Wait 30s, then check the server alerts
curl -H "X-API-Key: $ZAQORIN_API_KEY" \
  https://your-server/api/v1/alerts
```

You should see an alert with `tags: [attack.t1190]` and the
source IP from `curl`.

## Where to read more

- `docs/decisions/ADR-013-web-telemetry-foundation.md` — the
  design decision and trade-offs.
- `agent/pkg/webtail/` — the parsers and their test fixtures.
- `server/rules/builtin/mitre_attack/` — the Sigma rules.
