# Security Policy

ZaqorinCore is a defensive security tool. Taking the security of the project itself seriously is part of the job.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| latest  | ✅ Active          |
| older   | ❌ Best effort only |

Until we hit `v1.0.0`, only the `main` branch is supported. After `v1.0.0`, the latest minor release and the previous minor release receive security fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.** Public disclosure before a fix is shipped helps attackers more than it helps users.

Report privately via one of the following:

- **GitHub Security Advisories** — use the "Report a vulnerability" button on the [Security tab](https://github.com/Faris-stuck/zaqorincore/security/advisories/new) of this repository. This is the preferred channel.
- **Email** — open a GitHub issue titled `SECURITY: contact request` (no details in the issue body), and a maintainer will respond with an address.

We will:

1. Acknowledge your report within **72 hours**.
2. Triage within **7 days** and give you an initial assessment.
3. Coordinate disclosure timing with you. We aim to ship a fix within **30 days** for high-severity issues, and **90 days** for lower severity, but we will negotiate if the fix is complex.
4. Credit you in the release notes (unless you ask to remain anonymous).

## What is in scope

Anything that compromises the security of:

- The agent binary
- The central server
- The wire protocol between agent and server
- The dashboard (auth bypass, XSS, SSRF, etc.)
- The auto-response mechanism (command injection, unauthorized actions, etc.)
- The packaging / install scripts

## What is out of scope

- Denial of service against the central server (we rate-limit, but a determined attacker with bandwidth will win — that is the threat model)
- Issues in third-party dependencies that do not have a working exploit against ZaqorinCore
- Theoretical vulnerabilities with no realistic attack path
- "I can make my own server block me" — yes, you are the operator, that is by design

## Hardening notes for operators

- Run the central server behind a reverse proxy with TLS. The reference `docker-compose.yml` will do this for you.
- Keep the agent → server connection on a private network or a WireGuard mesh if you can.
- Rotate the per-agent shared secret on a schedule. The agent binary will support rotation from Phase 4 onward.
- Review the action history in the dashboard regularly. Auto-response can mask a misconfiguration.
- Use the `dry_run` mode for at least a week on any new detector before you let it block traffic.

## Cryptography choices

- WebSocket transport: TLS 1.3 only.
- Command signing: HMAC-SHA256 with a per-agent 256-bit shared secret. (No fancy curves here — this is a local control plane, not a public PKI.)
- Passwords (Phase 6): argon2id with the OWASP-recommended parameters.
- No custom crypto. We use the standard library / well-audited libraries only.

## Threat model (short version)

See [`ARCHITECTURE.md`](./ARCHITECTURE.md#threat-model-short-version) for the full version. Quick recap:

- We assume the agent's host is not yet compromised at install time.
- We assume the agent ↔ server network may be hostile (hence signed commands).
- We do not protect against an already-compromised host running our agent — at that point the operator has bigger problems.
