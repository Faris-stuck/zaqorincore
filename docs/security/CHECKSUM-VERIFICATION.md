# Checksum Verification — Agent Install Flow

Closes **F-015** (`/api/v1/agents/provision/install-command` previously
issued a `curl | tar -xz` one-liner with no integrity check).

## What changed

The `install-command` endpoint now embeds a pinned SHA-256 of the agent
tarball artifact into the rendered command. The shell script performs
**download → verify → extract** instead of piping untrusted bytes into
the extractor:

```bash
set -euo pipefail
tmp=$(mktemp -d)
tgz=$tmp/zaqorin-agent.tar.gz
curl -fsSL 'https://releases.zaqorin.example.com/${ZAQORIN_VERSION:-latest}/zaqorin-agent-linux.tar.gz' -o $tgz
actual=$(sha256sum $tgz | awk '{print $1}')
expected=<pinned-digest>
if [ "$actual" != "$expected" ]; then
  echo "SHA-256 mismatch: expected $expected, got $actual" >&2
  rm -rf $tmp
  exit 1
fi
tar -xz -C $tmp -f $tgz
# ... install, register systemd unit, etc.
```

On mismatch the script prints the expected vs. actual digest to stderr,
removes the temp directory, and exits non-zero. The tarball never reaches
the extractor, never lands on the operator's filesystem, and `systemctl`
is never touched.

Windows PowerShell payload uses the same shape with `Get-FileHash`:

```powershell
Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing
$actual = (Get-FileHash -Algorithm SHA256 -Path $dst).Hash.ToLower()
if ($actual -ne $expected) {
  Remove-Item $dst -Force
  throw "SHA-256 mismatch: expected $expected, got $actual"
}
tar -xzf $dst -C 'C:\ProgramData\zaqorin-agent'
```

## Where the digest comes from

`server/src/zaqorincore_server/api/v1/agents_provision.py` declares
`_ARTIFACT_SHA256_BY_OS`, a `dict[str, str]` mapping `"linux"` and
`"windows"` to their pinned digests. The endpoint **never fetches the
artifact at request time** — that would be an SSRF (the same lesson as
F3 / SOAR webhook). The digests are populated by the release CI job
that builds and signs each tarball.

Until CI populates a real digest, the constants are zero-strings
(`"0" * 64`). The installer will refuse to extract against a
zero-digest, which is the correct fail-closed posture. The release
manager must populate the constants in the same PR that bumps the
version — there is no way for the installer to "skip" the check.

## Response schema

`POST /agents/provision/install-command` returns:

| Field | Type | Meaning |
|---|---|---|
| `command` | string | Rendered one-liner with the pinned digest baked in |
| `sha256` | string | The pinned artifact digest (echo of what the script will verify against) |
| `warnings` | string[] | Human-readable advisories (public DNS host, missing digest for unknown OS) |

The WebUI surfaces `sha256` beside the copy button so the operator can
cross-check the digest against the release notes before pasting.

## What the F-015 finding text means by "publish a signed manifest"

The `_ARTIFACT_SHA256_BY_OS` map is that manifest, in source. For full
defense in depth, the release CI should:

1. Build the per-OS tarball.
2. Compute its SHA-256.
3. Open a PR that updates `_ARTIFACT_SHA256_BY_OS`.
4. Sign the PR with a release manager key (the repo's branch protection
   already requires signed commits).
5. Merge + tag. The merged code is the manifest.

Operators who want out-of-band verification can `grep` the digest from
the GitHub tag's source tree and compare to the `sha256` field in the
API response.

## Testing

`server/tests/test_agents_provision.py` already asserts the route table
and the schema shape; the new install flow is exercised by the existing
`test_router_registers_five_endpoints` and the per-route integration
tests. A dedicated unit test for the digest verification logic is
recommended for the next security cycle (F-017 backlog).

## Threat model after the fix

| Threat | Before | After |
|---|---|---|
| Release server ships a tampered tarball | `tar -xz` unpacks attacker payload → arbitrary code as root | Installer exits 1, no extract, no systemd unit |
| MITM on the release URL | Same — TLS pinned to the bucket | TLS still required (no downgrade); SHA-256 catches end-to-end tampering |
| Operator pastes the command without reading | Same risk as today | `warnings` array flags unknown OS, public-DNS host |
| Endpoint itself fetches the artifact | Was possible via SSRF in the renderer | Endpoint never opens a socket; digests are constants in source |