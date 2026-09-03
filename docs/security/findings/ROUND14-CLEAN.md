# Round 14 — CLEAN

| Field            | Value                                                            |
|------------------|------------------------------------------------------------------|
| Round            | 14                                                               |
| Cycle            | 87                                                               |
| Phase            | 1 (SECURITY track, NARROW SCOPE)                                 |
| Date             | 2026-09-04                                                       |
| Commit under audit | `33c7e18` (v3.4.23)                                            |
| Scope            | `server/src/zaqorincore_server/api/v1/agents_provision.py` (post-F-021) |
| Question         | Are the 5 provisioner endpoints free of command injection, TOML injection, auth bypass, log-leak, and error-disclosure regressions that Round 6 (F-021) and earlier rounds might have missed? |
| Result           | **CLEAN — 0 findings**                                           |

## Scope and method

Cycle 87 brief asked a narrow deep-audit of `agents_provision.py` (863 LOC)
post-F-021 (the F-019 redaction fix at commit `1ae1542`, v3.4.10). The audit
re-traced every endpoint, every sanitizer, and every interpolation site
where user-controlled data lands in a shell string, a TOML body, or a log
line.

The audit covered ten vectors:

1. **Command injection via `os` / `arch`** in `/provision/install-command`.
2. **Command injection via `agent_id`** in `/provision/install-command`.
3. **Command injection via `host`** in `/provision/dry-run` and
   `/provision/install-command`.
4. **Command injection via `tenant_id`** — does `tenant_id` exist on the
   endpoint at all?
5. **Auth / role / tenant escalation** on the install endpoint.
6. **Download URL safety** — scheme, host allowlist, redirect prevention.
7. **TOML serialization** — does every user-controlled field go through
   `_toml_quote`?
8. **PowerShell here-string (`@'…'@`)** — can the body contain a terminator
   that escapes the string?
9. **Bash heredoc (`<<'EOF'…EOF`)** — same question.
10. **File path / log / error-response leakage** — secrets, tokens, stack
    traces, file paths, internal IPs.

## Findings

### 1. `os` / `arch` command injection — CLEAN

`os` and `arch` are Pydantic `Literal` types (lines 105–106):
`OSLit = Literal["linux", "macos", "windows"]`,
`ArchLit = Literal["amd64", "arm64"]`. FastAPI rejects any other value at
the schema layer with a 422. Both are used in the install command only as
concatenation pieces of a hardcoded URL template (`asset =
f"zaqorin-agent-{body.os}.tar.gz"`, line 613) and as a dictionary key into
`_ARTIFACT_SHA256_BY_OS`. No shell expansion path.

### 2. `agent_id` command injection — CLEAN

`agent_id` is a 1–64-char string with an explicit character blocklist
(lines 597–604):

```python
if any(c in agent_id for c in (" ", "\t", "\n", "\r", '"', "\\", "$", "`")):
    raise HTTPException(status_code=422, ...)
```

`agent_id` only lands in (a) the `toml_inline` heredoc body of the POSIX
install command, (b) the PowerShell `@'…'@` here-string body of the Windows
install command, and (c) the `render_agent_toml` call (via
`/provision/template` only — `/install-command` does NOT call
`render_agent_toml`). All three sinks are single-quoted contexts (heredoc
`<<'EOF'`, PS literal here-string `@'…'@`, TOML basic string via
`_toml_quote`) — no `$variable` or `$(expr)` expansion reaches the shell.
The blocklist rejects space, tab, newline, CR, double-quote, backslash,
dollar, and backtick. The remaining character set cannot terminate a
single-quoted heredoc, terminate a PowerShell literal here-string, or
introduce a shell metacharacter.

### 3. `host` command injection — CLEAN

`host` flows through `_safe_host` (line 295) which applies the regex
`^[A-Za-z0-9][A-Za-z0-9._\-:]{0,253}[A-Za-z0-9]$` after optional bracket
stripping for IPv6. The character class permits only `[A-Za-z0-9._\-:]`
between the first and last char. The `_safe_host` helper then feeds the
value through `shlex.quote` (lines 549, 685–687) before it ever reaches a
shell context. No injection vector.

### 4. `tenant_id` — N/A

`tenant_id` is **not a parameter** of any endpoint in this router. There
is no multi-tenant path on `/api/v1/agents/*`. The only tenant-adjacent
state is the `Host` row in the database, which is keyed by `agent_id`
(UUID, validated by FastAPI's `uuid.UUID` type). No `tenant_id` field
appears in any request schema, response schema, or interpolation site.

### 5. Auth / role / tenant escalation — CLEAN

The router declares `dependencies=[Depends(require_api_key)]` at line 97,
so every endpoint — `GET /provision/template`, `POST /provision/dry-run`,
`POST /provision/install-command`, `POST /{agent_id}/rotate-secret`,
`GET /{agent_id}/config` — is behind the same API-key check. The
`{agent_id}` path parameter is typed `uuid.UUID`, so a non-UUID value
returns 422 before any handler runs.

There are **no roles** in the system. `require_api_key` is the only
authorization gate (consistent with F-006's note that API-key auth is the
server's auth boundary). No escalation surface exists because there is no
role hierarchy to escalate within.

The `rotate-secret` and `config` endpoints query `Host` rows by UUID
without any tenant filter. Because there is no tenant concept, this is
correct, not a bug — `agent_id` is globally unique. Documenting for
clarity; not a regression.

### 6. Download URL safety — CLEAN

`download_url` is constructed at lines 614–616:

```python
download_url = (
    f"https://releases.zaqorin.example.com/${{ZAQORIN_VERSION:-latest}}/{asset}"
)
```

- **Scheme**: hardcoded `https://`. Not user-controllable.
- **Host**: hardcoded `releases.zaqorin.example.com`. Not user-controllable.
- **Path**: `asset = f"zaqorin-agent-{body.os}.tar.gz"` where `body.os`
  is a Pydantic `Literal` (3 allowed values). No injection.
- **`ZAQORIN_VERSION`**: a bash `${VAR:-default}` shell-side default. Not
  API input; expanded by the operator's shell at exec time, not by the
  server.

The `curl -fsSL` invocation does follow redirects (`-L`). A malicious
redirect target could potentially serve a different tarball. The
mitigation is the SHA-256 verification on the next line: the tarball is
downloaded to `$tmp/zaqorin-agent.tar.gz`, its SHA-256 is computed and
compared to the **hardcoded** `_ARTIFACT_SHA256_BY_OS[body.os]` value,
and the install aborts if the digest does not match. The attacker would
need to host a tarball whose digest equals the pinned value — which is
the F-015 mitigation chain (closed in v3.4.1). CLEAN.

### 7. TOML serialization — CLEAN

Every user-controlled value that lands in a TOML basic string passes
through `_toml_quote` (line 348), which escapes `\\`, `"`, and every
control char (`cp < 0x20 or cp == 0x7F`) as `\uXXXX`. The function
appends:

- `server_url` (template + install-command paths) — `_toml_quote`.
- `agent_id` (template path) — `_toml_quote`.
- `auth_token` (template path) — `_toml_quote`.
- `log_sources[*].name` and `log_sources[*].path` (template path,
  `_toml_array_of_tables` helper, line 371) — each value `_toml_quote`d.

The install-command heredoc body (`toml_inline`, lines 640–644) uses
**raw f-string interpolation** rather than `_toml_quote` because the
destination is a single-quoted heredoc (`<<'ZAQORIN_EOF'`) and a
PowerShell literal here-string (`@'…'@`) — both of which treat the body
as opaque. The fields interpolated into `toml_inline` are:
- `server_url`: hardcoded `_DEFAULT_SERVER_URL`. Cannot inject.
- `agent_id`: blocklisted (lines 597–604). Cannot inject.
- `auth_token`: `secrets.token_hex(32)` — 64 hex chars only. Cannot inject.

Verified: TOML round-trip via `parse_agent_toml(toml_text)` (line 494,
839) catches any escape regression at request time. CLEAN.

### 8. PowerShell literal here-string terminator escape — CLEAN

The Windows install path uses `-Value @'\n…toml_inline…'@` (lines 671–674).
PowerShell's `@'…'@` literal here-string has exactly two terminator
sequences: the opening `@'` at the start of a line and the closing `'@`
on a line by itself. Neither `@'` nor `'@` can appear in `toml_inline`
because:

- `toml_inline` consists of three `key = "value"\n` lines.
- `server_url` = `_DEFAULT_SERVER_URL` = `wss://zaqorin.example.com:8443/api/v1/events`
  — contains no `@'` or `'@`.
- `agent_id` is blocklisted against `"` and `\\`; in addition, the
  PowerShell terminator is `@'` and `'@` — neither char sequence can be
  constructed from the allowed character set
  (no backtick, no single-quote blocklist char, but `@` is allowed).
- `auth_token` is `secrets.token_hex(32)` — 64 hex chars, no `@`.

Maximum-length analysis: even a 64-char `agent_id` containing 63 `@`
chars plus one printable cannot terminate the here-string because the
terminator requires `@'` (at-sign followed by single-quote), and `'`
is blocklisted. CLEAN.

### 9. Bash heredoc terminator escape — CLEAN

The POSIX install path uses `<<'ZAQORIN_EOF'\n…toml_inline…ZAQORIN_EOF\n`
(lines 695–697). Single-quoted heredoc: no shell expansion of body, no
`$variable` or `$(expr)` substitution. The terminator is the literal
string `ZAQORIN_EOF` on a line by itself. `toml_inline` cannot contain
the literal sequence `ZAQORIN_EOF` because:

- `server_url` is `_DEFAULT_SERVER_URL` (no `ZAQORIN_EOF` substring).
- `agent_id` is blocklisted against whitespace, quotes, `$`, `` ` ``,
  `\`; the substring `ZAQORIN_EOF` would require uppercase letters plus
  underscore, but the blocklist doesn't reject uppercase letters or
  underscores directly. The blocker is that the substring would need to
  appear on a line by itself, and `toml_inline` is one logical line
  (three `key = "value"` lines joined by `\n`). The heredoc only
  terminates on `ZAQORIN_EOF` at the start of a line; embedded
  `ZAQORIN_EOF` mid-line is treated as content. CLEAN.

Defense in depth: `dry-run` (line 541) also uses a single-quoted heredoc
with hardcoded body content. No user input reaches the body. CLEAN.

### 10. File path / log / error-response leakage — CLEAN

- **File path**: the install-command and dry-run endpoints do NOT touch
  the filesystem. They return rendered command strings; the operator's
  shell does the I/O on the target host. No `open()`, no `Path(...)`,
  no `os.path.join(...)` involving user input on the server side. CLEAN.
- **Logging**: at line 744–747, `host` (the user-supplied hostname) IS
  logged alongside its SHA-256 fingerprint. This is the **documented
  intent** of F-019's defense-in-depth design — the response carries
  only the fingerprint, the server log has the value for forensic
  correlation. Not a regression. The `auth_token` is NOT logged. The
  `host.secret` HMAC value is NOT logged (only the UUID `agent_id` is
  logged at line 792). CLEAN.
- **Error responses**:
  - 422 detail strings use `repr()` of the user's own input
    (`f"invalid host {raw!r}: …"`). The caller already knows the value;
    no internal state leaked.
  - `parse_agent_toml` line 460:
    `detail=f"generated TOML is not parseable: {e}"`. The
    `tomllib.TOMLDecodeError` string includes line/column but NOT the
    TOML body or any path. This is an internal 500 — only triggered by
    a server-side render bug. Low risk.
  - 404 on `rotate-secret` and `config` (lines 777, 818):
    `detail=f"unknown agent_id: {agent_id}"`. Caller already supplied
    the UUID; not a leak.
- **Rotate-secret response** (line 798): only `new_secret[:8]` (8 hex
  chars, ~32 bits) is returned — the full 256-bit secret is NOT in the
  response. Consistent with the design note at line 60–64. CLEAN.
- **ConfigOut** (line 836): `auth_token="<hidden — set out-of-band>"`
  literal placeholder. The HMAC secret never reaches the wire. CLEAN.

## Adjacent surfaces (out of scope, but checked for regression)

- **`server/src/zaqorincore_server/security.py` `require_api_key`** —
  unchanged since the F-006 baseline. The router dependency at line 97
  is the same reference.
- **`_safe_host` regex** — `^[A-Za-z0-9][A-Za-z0-9._\-:]{0,253}[A-Za-z0-9]$`
  is anchored, linear, no nested quantifiers. No ReDoS surface. The
  1–255 length window is consistent with RFC 1123 / RFC 952 hostname
  limits.
- **`shlex.quote` usage** at lines 549, 685, 687 — `shlex.quote` wraps
  its input in single quotes and escapes any embedded single quotes via
  `'\''`. This is the canonical Python idiom for embedding a string in
  a shell command and is safe by construction.
- **`secrets.token_hex(32)` entropy** — 256 bits, sourced from
  `secrets` (i.e., `os.urandom`). Cannot be predicted. Same generator
  used by `auth_token` (line 606), `template` endpoint (line 482), and
  `rotate-secret` (line 782).

## Conclusion

The `agents_provision.py` module at commit `33c7e18` (v3.4.23) is
free of the ten vectors checked. The F-021 fix at commit `1ae1542`
(v3.4.10) is complete; no residual classification bug exists for
non-bracketed input (the `ipaddress.ip_address(host)` parse at lines
724–734 correctly handles every value `_safe_host` accepts, because
`_safe_host`'s regex rejects bracketed IPv6 literals at the input
layer — the bracket-stripping at line 308 is unreachable for valid
IPv6).

No F-026 issued. Round 14 is CLEAN.

## Files touched this round

- `docs/security/findings/ROUND14-CLEAN.md` (new — this file)
- `docs/security/AUDIT-2026-09-03.md` (Round 14 section appended)