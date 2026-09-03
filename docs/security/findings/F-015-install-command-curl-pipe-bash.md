# F-015: `/api/v1/agents/provision/install-command` issues a `curl | bash` one-liner

| Field | Value |
|---|---|
| Severity | Low (by design) — Medium if the upstream URL becomes attacker-controlled |
| CWE | CWE-494 (Download of Code Without Integrity Check) |
| CVSS-like | 4.0 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L) |
| Location | `server/src/zaqorincore_server/api/v1/agents_provision.py:212-225`, `install-command` handler |
| Status | Acknowledged design (docstring explains it); low residual risk |

## Description

The agent provisioner generates a one-line installer of the form:

```
curl -fsSL https://releases.zaqorin.example/install.sh | sudo bash
```

The docstring is explicit:

> No actual SSH / network calls. The provisioner is purely a *plan* generator. It does
> not try to connect to the target host, does not write the install command to disk,
> and does not shell out. The WebUI takes the rendered command, shows it to the
> operator for review, and offers a copy-to-clipboard button. This is the same trust
> boundary as ``curl | bash`` itself: the operator eyeballs the command before pasting
> it.

What the docstring does **not** address:

1. The endpoint does not include any signature/SRI on the rendered installer URL. The
   returned `sha256` field is the hash of the **rendered command**, not the hash of
   the install script the URL will fetch. So a future compromise of the release server
   (`releases.zaqorin.example`) cannot be detected from the API response.
2. The default server URL is hardcoded (`_DEFAULT_SERVER_URL` on line 136) and points
   at `wss://zaqorin.example.com:8443/api/v1/events`. Operators who do not override
   this get a rendered installer pointing at the example domain.
3. There is no rate limit per-operator on `/install-command` (the global
   `RateLimitMiddleware` covers it but a single operator can still issue many
   one-time installer blobs, each one a potential pivot).

## Impact

* **Release-server compromise → arbitrary code execution on every fresh host.** If an
  attacker compromises the upstream URL the installer fetches, every operator who
  pastes the rendered command in the next 24 hours executes attacker-controlled code
  with `sudo`. The installer URL has no signature verification.
* **Supply-chain on the install script itself** — the install script is shipped via
  a CDN / release server whose security posture is invisible from this codebase.

## POC sketch

Not exploitable in this codebase; the risk is in the **upstream** that the rendered
command references. Phase 3 of the audit cannot verify the release server's posture.

## Remediation sketch

1. Compute and embed `sha256` of the actual install script artifact, not the rendered
   command. The endpoint cannot fetch it (that would be an SSRF; the same lesson from
   F3 applies), but a CI step could ship a signed manifest that the server reads.
2. Pin the upstream URL via a documented hash, not just a domain.
3. Document in `SECURITY.md` what release-server security guarantees the operator
   is relying on.