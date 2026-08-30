# ADR-013: Web telemetry foundation (nginx + ModSecurity)

**Status:** Accepted
**Date:** 2026-08-30
**Deciders:** ZaqorinCore maintainers

## Context

Until v1.7.6 ZaqorinCore was host-centric: the agent watched
syscalls, process exec, network flows, and Windows event logs.
It had zero coverage for web application attacks. A request
that looked like SQL injection to a WAF or a ModSecurity rule
was invisible to the agent. Users with public-facing web
applications — exactly the surface T1190 (Exploit Public-Facing
Application) targets — got no value from ZaqorinCore on that
attack class.

Three approaches were considered:

1. **Embedded WAF in the agent.** Re-implement OWASP ModSecurity
   Core Rule Set inside the Go binary. Rejected: reinvents a
   battle-tested engine; thousands of person-years of CRS rules
   would have to be ported; the agent binary balloons; the
   rules lag behind CRS by definition.
2. **Hook into nginx directly via Lua or dynamic modules.**
   Rejected: requires operator to install a custom nginx build;
   no portable deployment story; no benefit over tailing the
   log file the operator already runs.
3. **Tail the existing nginx access log and the ModSecurity
   audit log, parse the lines into structured fields, attach
   them as event metadata, and let the existing Sigma engine
   correlate them.** Chosen.

## Decision

Add a new package `pkg/webtail` that contains two parsers:

- `ParseNginxLine` — parses nginx `combined` log format into a
  `map[string]string` of fields (src_ip, http_method, uri,
  status_code, bytes_sent, referer, user_agent, auth_user).
- `ParseModSecLine` — parses one line of a ModSecurity audit
  log (section markers, headers, value lines) and returns the
  section letter and field map.

The parsers are pure functions (no I/O, no channels, no
goroutines). They do not know about the wire schema — the
caller in `internal/app` attaches the parsed fields to
`event.Event.Metadata`, which the existing transport already
serialises.

A new constant `event.SourceModSecAudit = "modsec_audit"` is
added alongside the existing `SourceNginxAccess` /
`SourceNginxError`. The wire-injection point is one line in
`internal/app/app.go`: after `event.New(...)` and before
`tr.Send(...)`, call `enrichWithWebParser(&ev, logger)`. The
enrichment is best-effort: unrecognised lines (heartbeats,
custom log_format, blank logrotate lines) are passed through
untouched so the server can still index the raw text.

Two new Sigma rules ship with this change:

- `T1110_http_brute_force.yml` — 10 HTTP 401/403 responses
  from a single src_ip in 60 seconds.
- `T1190_http_method_anomaly.yml` — TRACE / DEBUG / PROPFIND
  / etc. methods (XST, API enumeration, server-side
  misconfiguration).

These join the existing `T1190_exploit_public_app.yml` and
`web_attack.yml` rules to give a baseline of web-layer
detection that mirrors what an enterprise WAF would emit.

## Consequences

**Positive**

- Web-layer attacks now generate ZaqorinCore alerts with the
  same chain-of-custody, auto-response (block_ip, evidence
  capture), and dashboard visibility as host-layer attacks.
- Operators do not need to install a custom nginx build or
  a sidecar. The existing `tailer.New(src, logger)` already
  reads any text file with a `LogSource` config entry.
- Future CDN adapters (Cloudflare Logpush, AWS CloudFront
  access logs, Fastly) can re-use the wire-injection hook
  with their own parser package — no app.go change needed.

**Negative**

- The agent only sees what nginx/ModSecurity writes to disk.
  If access logs are dropped by logrotate before the agent
  reads them, the gap is invisible. Operators must size
  log retention accordingly (or pipe to a FIFO the agent
  holds open).
- Combined log format is parsed; custom `log_format` is
  rejected. Operators who use a custom format must
  reconfigure nginx to emit `combined` or extend
  `ParseNginxLine` with a new branch.
- The parsers are keyword-based, not parser-based, for
  attack patterns. A request that encodes its attack
  payload in a header (rather than the URI) will not match
  the `web_attack.yml` rule. ModSecurity in front of nginx
  remains the recommended defense-in-depth; the agent is the
  detection and response layer, not the prevention layer.

## What this ADR does NOT cover

- Active response specific to web (e.g. request-blocking
  by URI). Out of scope: ZaqorinCore responds at the network
  layer (block_ip, tarpit_ip), not the application layer.
- TLS termination inspection. Out of scope: the agent sees
  the post-termination access log, not the ciphertext.
- Distributed rate-limiting across multiple agents. Each
  agent watches its own logs. Future work: central
  correlation by the server's Sigma engine.
