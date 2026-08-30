# ADR-014: CDN adapter (Horizon 2)

**Status:** Accepted
**Date:** 2026-08-30
**Deciders:** ZaqorinCore maintainers
**Supersedes:** none
**Related:** ADR-013 (web telemetry foundation), v1.7.7

## Context

Until v1.7.7, ZaqorinCore had host-centric coverage (agent on
Linux/Windows) plus web server coverage (nginx + ModSecurity
parsers). Two thirds of the production fleet is not in either
bucket: sites that sit behind a CDN, SaaS companies that rely
on Cloudflare/CloudFront/Fastly, and startups that ship
client-side code with no server they own. The "universal
coverage for perusahaan + startup + individu" target needs an
edge-ingest path that does not require running the agent on
the origin.

## Decision

Add a CDN-ingest path on the server side. It accepts
structured web access logs from CDNs over HTTPS, verifies
their authenticity, parses them with the same webtail-derived
field schema, and feeds them into the existing Sigma engine
as if they came from the agent. No new detection logic — the
Sigma rules from v1.7.7 and earlier are reused unchanged.

The first two vendors are Cloudflare Logpush (push-based,
NDJSON) and a generic webhook (one adapter, header-driven
source detection). AWS CloudFront (Kinesis-stream based) and
Fastly (push-based, NDJSON) are deferred — they have the same
shape and will be straightforward extensions.

### Path: Cloudflare Logpush (`/api/v1/ingest/cloudflare`)

- **Wire format:** NDJSON. One Cloudflare HTTP request record
  per line. Each line is the JSON object documented at
  https://developers.cloudflare.com/logs/log-fields/zone/http_requests/.
  ZaqorinCore parses a known subset of fields — see
  `ingest_cloudflare.py` for the explicit allowlist.
- **Auth model:** Cloudflare Logpush does not natively sign
  the body. The user configures a custom HTTP header on the
  push job (e.g. `X-ZaQorin-Signature`). ZaqorinCore reads
  that header, computes HMAC-SHA256 of the raw request body
  with a shared secret from `ZAQORIN_CLOUDFLARE_INGEST_SECRET`,
  and compares with `hmac.compare_digest`. Constant-time.
  Failed auth returns 401 with empty body.
- **Why this is safe enough:** The shared secret is
  ZaqorinCore-side, not Cloudflare-side. If Cloudflare's
  edge is compromised, the secret can be exfiltrated. The
  threat model accepts that — the same as accepting a SIEM
  API key. The win is that the path is *not* a backdoor:
  every line is validated, every rejected line is counted,
  every accepted line is logged with the request's source
  IP and event source.
- **Body cap:** 5 MiB. Cloudflare batches are typically
  1-2 MiB; 5 MiB is a 2.5x headroom. Lines above 64 KiB are
  rejected individually (the rest of the batch is still
  accepted) — same pattern as the agent's `pkg/webtail` 1MB
  cap, tighter because we know the field schema.
- **Metadata values** are truncated to 4 KiB before
  persistence. Cloudflare URIs and User-Agents can be
  arbitrarily long; the truncation prevents an attacker
  (or a misbehaving WAF) from filling the database with a
  single multi-MB string.

### Path: Generic webhook (`/api/v1/ingest/webhook`)

- **Wire format:** JSON body. Two shapes supported:
  - Single object: `{"src_ip": "...", "uri": "...", ...}`
  - Batch: `{"events": [{...}, {...}]}`
  Field names match the existing metadata keys from
  `pkg/webtail` and the Cloudflare ingest path.
- **Auth model:** Same X-ZaQorin-Key as the rest of the API
  (F6). Different secret from the Cloudflare path — a
  generic webhook is lower-trust than a CDN-signed path.
- **Source detection:** By request body `source` field, or
  by `X-Event-Source` header. Falls back to `webhook`.
- **Why a generic path at all:** SIEM-to-SIEM forwarding
  (Splunk HEC, Elastic Webhook, Sumo Logic) wants an
  adapter per vendor. A generic JSON webhook lets us accept
  Splunk's output and translate field names server-side
  instead of writing N vendor adapters. The first
  translation table is a 10-line dict in
  `ingest_webhook.py`. Adding a new vendor is a one-line
  addition to the dict, not a new endpoint.

### Detection rules (Slice C, separate commit)

Six new Sigma rules in `server/rules/builtin/mitre_attack/`,
all using the existing field schema (no new fields). Levels
and tags documented per rule. None of them require a
specific event source — they match by field presence, so
the same rule fires whether the event came from the agent
or from a CDN push.

### What we are NOT building in Horizon 2

- **AWS CloudFront Kinesis receiver.** CloudFront ships
  access logs to Kinesis Data Streams, not to a webhook. The
  ingest path is a separate Kinesis consumer (Go or Python).
  Deferred to Horizon 2.5.
- **Fastly, Akamai, Vercel, Netlify.** Same shape as
  Cloudflare Logpush. Deferred — the generic webhook
  already covers them if their fields are translated
  client-side.
- **Bi-directional CDN control (purge cache, set
  rate-limit rules).** Out of scope. ZaqorinCore is
  detection, not control plane. If a user wants SOAR actions
  on a CDN, that is a separate `action` kind with its own
  ADR.

## Consequences

### Positive

- **Coverage expands from "web servers I run" to "any web
  property with CDN access logs".** This is the difference
  between "a WAF for sysadmins" and "a WAF for
  product teams". The market for the latter is much larger.
- **Zero new dependencies.** Both endpoints use the existing
  FastAPI + Pydantic + sqlalchemy stack. No vendor SDKs.
- **Detection reuses.** Six new Sigma rules, but the engine
  is unchanged. This is by design — Sigma rules are the
  user-facing detection surface, not the engine.
- **Symmetric ingest with the agent.** Both paths end up in
  the same `events` table with the same `metadata` schema.
  The Sigma engine and the dashboard do not care where an
  event came from. This means the user does not have to
  think about ingest source when they write a rule.

### Negative / Risks

- **HMAC verification is the only auth on the Cloudflare
  path.** A leaked secret = full read access to the user's
  push channel. The secret must be rotated manually (no
  automatic rotation). Document this in the operator guide
  and link to a key-rotation runbook.
- **Body parsing is best-effort.** A malformed line is
  rejected, not failed. This means a noisy source can
  silently drop events. Counter: the response includes
  `{accepted, rejected}` counts, and a 100% rejection rate
  is loud enough to surface in any monitoring.
- **Field name mapping is fixed.** If Cloudflare changes a
  field name in a future Logpush schema change, the parser
  needs an update. The parser is intentionally
  forward-compatible: unknown fields are ignored, not
  rejected.
- **No replay protection.** A captured request can be
  replayed within the HMAC-secret lifetime. The accepted
  payload has its own schema-version field, so a replay
  after a rotation is automatically rejected when the
  secret changes.

## Alternatives considered

1. **CDN-side WAF instead of detection.** Rejected. The
   whole point of ZaqorinCore is detection, not prevention.
   A CDN-side WAF is also vendor lock-in. Users who want a
   WAF already have one — they came to ZaqorinCore for the
   detection layer.
2. **Run the agent on the CDN edge.** Rejected. Cloudflare
   Workers are a different runtime with a different
   deployment model. The cost of supporting it (limited
   language, limited I/O, limited CPU) outweighs the benefit
   for a defensively-focused product.
3. **One endpoint per CDN vendor.** Rejected. Splunk HEC
   has the same shape. Elastic Webhook has the same shape.
   A generic JSON webhook covers 80% of the long tail.
4. **Push from CDN into the existing agent stream.** The
   agent already speaks a WebSocket frame format. Could we
   forward CDN events through the agent? Yes, but the
   agent has its own auth model (HMAC over a session
   challenge). Translating a server-side CDN push into a
   forged WebSocket HELLO frame is more code than just
   reading the body with FastAPI and inserting into the
   same database.

## Implementation plan

Three slices, each independently shippable and taggable:

- **Slice A (Horizon 2.0):** Cloudflare Logpush ingest
  endpoint with HMAC verification. ~200 LOC, 8 tests.
- **Slice B (Horizon 2.1):** Generic webhook endpoint with
  header-based source detection and field-name translation
  table. ~150 LOC, 6 tests.
- **Slice C (Horizon 2.2):** Six CDN-specific Sigma rules.
  No new code, just YAML. 6 tests.

Each slice ends with a Cybersec review (Bot pattern), a
pre-tag commit, a version bump, and a GH Release.

## Open questions

- Should we surface CDN-region as a Sigma field? It would
  let users write geo-aware rules. The Cloudflare fields
  are there; we just don't ingest them yet. Defer until a
  user asks — YAGNI applies.
- Should the generic webhook support a `severity` field
  from the sender, so a SIEM can pre-classify? The existing
  Sigma engine computes severity from rule matches; mixing
  pre-classified and computed severity is a recipe for
  confusion. Reject for now.
