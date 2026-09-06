# ZaqorinCore Full Security Audit — 2026-09-06

## Scope

Static source audit of the public `main` branch covering the Go agent, Python server, WebSocket protocol, authentication, auto-response, provisioning, dependency metadata, and CI security controls.

Runtime exploitability was not independently proven on a live deployment. Findings are marked as source-verified where the vulnerable behavior follows directly from the code path.

## Executive summary

The audit found multiple security and correctness defects. The highest impact issues were protocol incompatibility between the agent and server, fail-open API authentication, unauthenticated host-row creation during WebSocket handshake, replayable auto-response commands, and containment actions whose documented TTL did not actually expire the installed firewall rule.

Remediation has been committed directly to `main` during this audit. CI is still not green at the time of writing, so this branch must not be labelled production-ready until the remaining test/build failures are resolved and an end-to-end authenticated handshake is exercised.

## Findings

### ZAQ-001 — Critical — WebSocket protocol mismatch
- File: `agent/internal/transport/transport.go`, `server/src/zaqorincore_server/api/v1/stream.py`, `server/src/zaqorincore_server/schemas/wire.py`
- CWE: CWE-400 (availability impact from protocol incompatibility)
- CVE: N/A — project integration defect
- Attack path: attacker/normal deployment connects an agent -> server sends challenge v2 -> legacy agent sends HELLO v1 without nonce/signature -> server rejects the protocol -> agent repeatedly reconnects and cannot ingest events or receive response commands.
- Evidence: server requires `v=2`, nonce echo, and HMAC signature; the former agent HELLO contained only `type`, `agent_id`, and `version`.
- Remediation: agent now implements challenge/HMAC v2; server schema is explicit about v2 fields.

### ZAQ-002 — High — API authentication fail-open
- File: `server/src/zaqorincore_server/auth.py`, `server/src/zaqorincore_server/config.py`
- CWE: CWE-306 (Missing Authentication for Critical Function)
- CVE: N/A
- Attack path: deploy server without API-key environment variables -> protected routers call `require_api_key` -> old auth dependency returned `Role.WRITE` -> attacker could call administrative endpoints without credentials.
- Evidence: old `require_role()` explicitly returned `Role.WRITE` when no credentials existed.
- Remediation: default is now fail-closed; unauthenticated mode requires explicit `ZAQORIN_ALLOW_UNAUTHENTICATED=true` and logs a warning.

### ZAQ-003 — High — Host provisioning before WebSocket authentication
- File: `server/src/zaqorincore_server/service/host_service.py`, `server/src/zaqorincore_server/api/v1/stream.py`
- CWE: CWE-306 / CWE-400
- CVE: N/A
- Attack path: unauthenticated WebSocket sends arbitrary UUID -> server creates/updates Host record before proving possession of its secret -> attacker can pollute persistent host state.
- Remediation: handshake now requires an already-provisioned Host; unknown agents are rejected instead of auto-created.

### ZAQ-004 — High — Command replay window
- File: `agent/internal/response/response.go`
- CWE: CWE-294 (Authentication Bypass by Capture-Replay)
- CVE: N/A
- Attack path: attacker captures a valid signed COMMAND frame -> replays it after the former 60-second duplicate cache expires -> HMAC remains valid because timestamp freshness was not enforced -> privileged action can repeat.
- Remediation: `issued_at` is now RFC3339-parsed and restricted to a five-minute clock-skew window; applied command IDs are retained with bounded memory.

### ZAQ-005 — High — Tarpit TTL did not remove the firewall rule
- File: `agent/internal/response/kinds/kinds.go`, `agent/internal/response/kinds/ttl_actions.go`
- CWE: CWE-672 (Operation on a Resource after Expiration)
- CVE: N/A
- Attack path: signed `tarpit_ip` command -> nftables rule installed -> TTL elapses -> old implementation only logged that an operator should clean it up -> mitigation remains active indefinitely.
- Remediation: new executor uses an nftables timeout set element so expiration is enforced by nftables itself.

### ZAQ-006 — High — Host isolation TTL did not roll back
- File: `agent/internal/response/kinds/kinds.go`, `agent/internal/response/kinds/ttl_actions.go`
- CWE: CWE-672
- CVE: N/A
- Attack path: signed `isolate_host` -> output DROP rule inserted -> TTL ignored -> host stays isolated until manual intervention.
- Remediation: isolation rule receives a unique comment and a delayed exact-handle deletion; no unrelated rules are flushed.

### ZAQ-007 — High — Auto-response local policy was not enforced
- File: `agent/internal/config/config.go`, `agent/internal/response/response.go`
- CWE: CWE-862 (Missing Authorization)
- CVE: N/A
- Attack path: operator config disables a response capability -> server sends a valid HMAC COMMAND for that capability -> old handler dispatches solely on `cmd.Kind` -> disabled local action is still eligible.
- Remediation: explicit per-action allow flags are now checked before dispatch; unknown/new action kinds default deny.

### ZAQ-008 — Medium — TLS 1.3 policy was documented but not enforced
- File: `SECURITY.md`, `agent/internal/transport/transport.go`
- CWE: CWE-757 (Selection of Less-Secure Alternative)
- CVE: N/A
- Evidence: security policy states TLS 1.3 only while the former WebSocket dialer did not set MinVersion/MaxVersion.
- Remediation: WSS now pins TLS 1.3; insecure `ws://` is allowed only for loopback development fixtures.

### ZAQ-009 — Medium — Windows log-source template incompatible with agent validation
- File: `server/src/zaqorincore_server/api/v1/agents_provision.py`, `agent/internal/config/config.go`
- CWE: CWE-20 (Improper Input Validation)
- CVE: N/A
- Attack path: provision Windows config -> template emits `Security`/`System` as paths -> agent validation requires absolute paths -> startup rejects generated config.
- Remediation status: identified; generator must be aligned with the Windows Event Log backend rather than file-tail path validation. This item is not claimed fully remediated by the current patch set.

### ZAQ-010 — Medium — Secret rotation is not an atomic end-to-end rollout
- File: `server/src/zaqorincore_server/api/v1/agents_provision.py`, `agent/cmd/zaqorin-agent/main.go`
- CWE: CWE-693 (Protection Mechanism Failure)
- CVE: N/A
- Attack path: operator rotates server secret -> server immediately stores secret B -> agent still authenticates with secret A -> fleet member disconnects until out-of-band secret deployment.
- Additional correctness issue: endpoint documentation called rotation idempotent, but each request generates a fresh secret.
- Remediation status: not fully solved by source patch; requires staged rotation or dual-secret overlap protocol.

### ZAQ-011 — Medium — Arbitrary local file path accepted by canary action
- File: `agent/internal/response/kinds/kinds.go`
- CWE: CWE-73 (External Control of File Name or Path)
- CVE: N/A
- Attack path: trusted/signed command supplies an arbitrary absolute path -> agent writes the canary marker wherever its service identity has permission.
- Remediation status: not fully solved; recommended control is a dedicated canary root with path canonicalization and confinement.

### ZAQ-012 — Medium — Webhook action is an agent-side SSRF primitive
- File: `agent/internal/response/kinds/kinds.go`
- CWE: CWE-918 (Server-Side Request Forgery)
- CVE: N/A
- Attack path: valid server command controls URL -> agent `curl` reaches arbitrary HTTP/HTTPS destination visible from the protected host.
- Mitigation already present: only HMAC-authenticated commands reach this executor. Recommended hardening is an allowlist of SOAR destinations and explicit denial of loopback/link-local/private destinations unless configured.

### ZAQ-013 — Medium — Dependency vulnerable on supported Windows code path
- File: `agent/go.mod`, `agent/go.sum`
- CWE: N/A (third-party dependency vulnerability)
- CVE: CVE-2026-39824
- Affected advisory: GO-2026-5024. `golang.org/x/sys` before v0.44.0 is affected for `golang.org/x/sys/windows.NewNTUnicodeString`.
- Remediation: `x/sys` upgraded to v0.44.0 and Go module baseline raised to Go 1.25.0. Go 1.27.1 is the current latest major-series release as of the audit date, and Go 1.25.14 is the current 1.25 minor revision; CI has been moved to supported 1.25/1.27 toolchains.

### ZAQ-014 — Medium — Security CI had a broken SARIF artifact chain
- File: `.github/workflows/security-audit.yml`
- CWE: N/A — CI control failure
- CVE: N/A
- Evidence: the workflow referenced `server/pip-audit.sarif` and an artifact named `pip-audit-sarif`, while the shown audit step ran `pip-audit` without producing/uploading that SARIF artifact.
- Remediation status: identified but not fully rewritten in this patch sequence; the audit result must not be interpreted as complete until this workflow is validated end-to-end.

## Positive controls verified

- HMAC-SHA256 uses constant-time comparison.
- Agent secret file uses 0600 permissions and state directory 0700 after remediation.
- WebSocket frame size limits exist on the server and depth-limited JSON parsing is used for hostile input.
- API role comparisons use `hmac.compare_digest`.
- Security headers middleware includes CSP, frame denial, MIME sniffing protection, and a restrictive permissions policy.
- Agent command execution uses argument-vector APIs rather than a shell command interpreter for the nft/curl/process actions inspected.

## Patch ledger

Committed directly to `main` during this audit:

- WebSocket v2 challenge/HMAC authentication alignment.
- Fail-closed API authentication with explicit development override.
- No auto-creation of hosts during WebSocket handshake.
- Command freshness + replay suppression.
- Per-action local response authorization.
- TLS 1.3 enforcement for WSS.
- Secret/state filesystem permission tightening.
- Real TTL behavior for tarpit/isolation containment paths.
- Updated response tests for freshness semantics.
- Go `x/sys` security upgrade and Go toolchain baseline update.
- CI Go matrix update.

## Validation status

The repository's GitHub Actions have been triggered repeatedly during remediation. At the time of this report, recent runs were still failing, and the connector could not expose usable step logs for the failing jobs. Therefore this audit explicitly does NOT claim that the current `main` branch is build-green or production-ready.

The remaining release gate is: obtain a green Go unit/build pipeline, green Python test/lint pipeline, and a real authenticated agent/server WebSocket integration test covering challenge, valid signature, invalid signature, replay rejection, command authorization, and TTL rollback.
