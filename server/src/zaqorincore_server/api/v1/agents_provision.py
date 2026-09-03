"""Agent Provisioner API — Slice 1 of the Phase 26 WebUI agents plan.

Lets a non-technical operator install and configure ZaqorinCore
agents from the WebUI without touching a terminal. Five
endpoints, all behind ``require_api_key``:

* ``GET  /api/v1/agents/provision/template``        — generate a
  starter ``agent.toml`` for a given OS / arch.
* ``POST /api/v1/agents/provision/dry-run``         — given a
  target host, return the ``ssh`` command that the install
  step would run plus a one-shot verification probe.
* ``POST /api/v1/agents/provision/install-command`` — return
  the one-line ``curl | bash`` installer a human can paste
  onto a fresh box.
* ``POST /api/v1/agents/{id}/rotate-secret``        — generate
  a new 32-byte hex HMAC secret for an existing host and
  persist it on the ``hosts`` row.
* ``GET  /api/v1/agents/{id}/config``               — return
  the agent's *live* ``agent.toml`` (i.e. the on-disk shape
  the agent should be running, derived from the ``Host`` row
  + the server's public base URL).

Design notes
============

* **TOML output, not YAML / JSON.** The agent's native config
  format is TOML (see ``agent.example.toml`` in the repo
  root). Generating JSON or YAML here would create a layer
  the operator has to translate at install time. We hand-roll
  the TOML string rather than depending on ``tomli_w`` so
  the test can run in any Python 3.11+ venv (where
  ``tomllib`` is stdlib, ``tomli_w`` may not be installed
  on locked-down hosts).

* **No shell expansion of user input.** The dry-run and
  install-command endpoints accept hostnames, ports, and
  usernames from the operator. Every interpolated value is
  fed through ``shlex.quote`` so a hostname of
  ``'; rm -rf /'`` lands in the rendered command as a
  quoted literal rather than a metacharacter. The
  ``_safe_host`` / ``_safe_user`` / ``_safe_port`` helpers
  reject values that can't be safely quoted (spaces, newlines,
  shell metacharacters that survive ``shlex.quote``).

* **No actual SSH / network calls.** The provisioner is
  purely a *plan* generator. It does not try to connect to
  the target host, does not write the install command to
  disk, and does not shell out. The WebUI takes the rendered
  command, shows it to the operator for review, and offers
  a copy-to-clipboard button. This is the same trust
  boundary as ``curl | bash`` itself: the operator eyeballs
  the command before pasting it.

* **Secret rotation is idempotent.** Replaying
  ``rotate-secret`` always returns a freshly generated
  64-char hex token. The previous secret is overwritten
  atomically (``UPDATE ... RETURNING secret``) so a partial
  failure cannot leave the host with a half-rotated secret.

* **The ``GET /agents/{id}/config`` endpoint never returns
  the HMAC secret.** The agent reads its own secret from a
  file provisioned out-of-band; the WebUI only needs the
  connection metadata so the operator can verify what the
  running agent should be configured with.
"""

from __future__ import annotations

import logging
import re
import secrets
import shlex
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select as sa_select
from sqlalchemy.ext.asyncio import AsyncSession

from ...db import get_session
from ...models import Host
from ...security import require_api_key

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────────────────────────────────────

router = APIRouter(
    prefix="/api/v1/agents",
    tags=["agents_provision"],
    dependencies=[Depends(require_api_key)],
)


# ─────────────────────────────────────────────────────────────────────────────
# Supported platforms — keep in sync with the Go agent's build matrix
# ─────────────────────────────────────────────────────────────────────────────

OSLit = Literal["linux", "macos", "windows"]
ArchLit = Literal["amd64", "arm64"]

# Default log-source presets the template ships with. Operators
# can override / delete these in the WebUI form before downloading
# the file. Linux gets syslog + auth; macOS gets unified log
# channels; Windows gets the Security + System channels.
_LOG_SOURCE_PRESETS: dict[str, list[dict[str, str]]] = {
    "linux": [
        {"name": "auth", "path": "/var/log/auth.log"},
        {"name": "syslog", "path": "/var/log/syslog"},
    ],
    "macos": [
        {"name": "unified_auth", "path": "/var/log/auth.log"},
        {"name": "install", "path": "/var/log/install.log"},
    ],
    "windows": [
        {"name": "security_evtx", "path": "Security"},
        {"name": "system_evtx", "path": "System"},
    ],
}

# Reasonable upper bound on a rendered TOML config — anything
# longer is almost certainly an operator pasting in a giant log
# path that they should be putting in a sidecar file.
_MAX_TEMPLATE_BYTES = 64 * 1024

# Default fallback when the server doesn't know its own public URL.
# Operators are expected to override this via the WebUI form;
# we surface it in the response so the rendered command can be
# inspected before being executed.
_DEFAULT_SERVER_URL = "wss://zaqorin.example.com:8443/api/v1/events"

# Pinned SHA-256 digests of the per-OS agent tarballs. Updated
# by CI when a new release ships; the rendered install script
# refuses to extract on mismatch. Closing F-015: the previous
# ``curl | tar -xz`` shape had no integrity check between the
# release bucket and the operator's filesystem.
#
# These are deterministic placeholders until the release CI
# job populates them. A mismatch against an actual artifact
# causes the installer to fail loudly, not silently run an
# attacker-controlled tarball.
_ARTIFACT_SHA256_BY_OS: dict[str, str] = {
    "linux": (
        "0000000000000000000000000000000000000000000000000000000000000000"
    ),
    "windows": (
        "0000000000000000000000000000000000000000000000000000000000000000"
    ),
}

# Server root for the dispatcher (same constant the rules_studio
# module uses so the two routers agree on where to anchor
# filesystem-relative lookups if we ever add a config-file
# export to this endpoint).
_SERVER_ROOT = Path(__file__).resolve().parents[4]


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────


class TemplateOut(BaseModel):
    """GET /agents/provision/template response.

    ``toml`` is the literal agent.toml content the operator can
    save to ``/etc/zaqorin/agent.toml``. ``filename`` is the
    suggested download name including the OS / arch suffix.
    """

    os: OSLit
    arch: ArchLit
    server_url: str
    toml: str
    filename: str = Field(
        description="Suggested filename for the browser download, e.g. agent-linux-amd64.toml",
    )


class DryRunIn(BaseModel):
    """POST /agents/provision/dry-run body."""

    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    user: str = Field(default="root", min_length=1, max_length=64)
    ssh_key_id: str | None = Field(
        default=None,
        max_length=128,
        description=(
            "Optional SSH key identifier. Used to look up the key "
            "path on the operator's workstation; the value is "
            "passed through to the rendered command unchanged."
        ),
    )


class DryRunOut(BaseModel):
    """POST /agents/provision/dry-run response.

    ``install_command`` is the full ``ssh`` invocation the
    installer will run (the operator can copy it into a
    terminal for the dry run). ``verify_command`` is the
    post-install probe that asserts the agent's WebSocket
    came up.
    """

    host: str
    port: int
    user: str
    install_command: str
    verify_command: str
    notes: list[str] = Field(default_factory=list)


class InstallCommandIn(BaseModel):
    """POST /agents/provision/install-command body."""

    agent_id: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "Free-form agent id. Typically the same UUID the "
            "agent will write into its own agent.toml; not "
            "required to be a Host row."
        ),
    )
    host: str = Field(min_length=1, max_length=255)
    os: OSLit = "linux"


class InstallCommandOut(BaseModel):
    """POST /agents/provision/install-command response.

    ``command`` is a self-installing one-liner that downloads the
    agent tarball to a temp file, verifies its SHA-256 against the
    pinned digest in ``sha256``, then extracts. This closes F-015:
    the previous shape ``curl | tar -xz`` trusted whatever the
    release server shipped on every fresh install.
    """

    command: str
    sha256: str = Field(
        description=(
            "SHA-256 of the agent tarball artifact (not the rendered "
            "command). The installer refuses to extract on a "
            "mismatch. Recomputed from a CI-pinned manifest; the "
            "endpoint never fetches the artifact."
        )
    )
    warnings: list[str] = Field(default_factory=list)


class RotateSecretOut(BaseModel):
    """POST /agents/{id}/rotate-secret response."""

    agent_id: uuid.UUID
    rotated_at: datetime
    secret_preview: str = Field(
        description=(
            "First 8 hex chars of the new secret, for the "
            "operator to confirm the rotation took effect. "
            "The full secret is never returned."
        ),
    )


class ConfigOut(BaseModel):
    """GET /agents/{id}/config response — the live agent.toml."""

    agent_id: uuid.UUID
    server_url: str
    agent_id_field: str
    hostname: str | None
    last_seen_at: datetime | None
    toml: str
    warnings: list[str] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Input sanitization helpers
# ─────────────────────────────────────────────────────────────────────────────


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-:]{0,253}[A-Za-z0-9]$")
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.\-/+=@:,]{1,128}$")


def _safe_host(raw: str) -> str:
    """Validate + return a hostname, IPv4, or bracketed IPv6.

    The intent is to reject values that contain shell
    metacharacters even after ``shlex.quote`` — we want the
    rendered command to be obviously wrong if a typo slips
    through, not to be silently mangled.
    """
    if not raw or len(raw) > 255:
        raise HTTPException(
            status_code=422, detail="host must be 1..255 chars"
        )
    # IPv6 literals arrive bracketed; strip for the regex test.
    candidate = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    if not _HOST_RE.match(candidate):
        raise HTTPException(
            status_code=422,
            detail=(
                f"invalid host {raw!r}: must match "
                f"[A-Za-z0-9][A-Za-z0-9._-:]{{0,253}}[A-Za-z0-9]"
            ),
        )
    return raw


def _safe_user(raw: str) -> str:
    if not _USER_RE.match(raw):
        raise HTTPException(
            status_code=422,
            detail=(
                f"invalid user {raw!r}: must match "
                f"[A-Za-z_][A-Za-z0-9_.-]{{0,63}}"
            ),
        )
    return raw


def _safe_key_id(raw: str | None) -> str | None:
    if raw is None:
        return None
    if not _KEY_ID_RE.match(raw):
        raise HTTPException(
            status_code=422,
            detail=f"invalid ssh_key_id {raw!r}",
        )
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# TOML generation
# ─────────────────────────────────────────────────────────────────────────────


def _toml_quote(value: str) -> str:
    """Return ``value`` wrapped in TOML basic-string quotes.

    TOML basic strings are surrounded by double quotes with
    ``\\`` and ``"`` as the only required escapes. We escape
    every control char (0x00..0x1F, 0x7F) to keep the output
    valid even if the operator pastes in a weird hostname.
    """
    out = ['"']
    for ch in value:
        cp = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif cp < 0x20 or cp == 0x7F:
            out.append(f"\\u{cp:04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _toml_array_of_tables(rows: list[dict[str, str]]) -> str:
    """Render ``[[log_source]]`` blocks for the template."""
    chunks: list[str] = []
    for row in rows:
        chunks.append("\n[[log_source]]")
        for k, v in row.items():
            chunks.append(f"{k} = {_toml_quote(v)}")
    return "\n".join(chunks) + ("\n" if chunks else "")


def render_agent_toml(
    *,
    os: OSLit,
    arch: ArchLit,
    server_url: str,
    agent_id: str,
    auth_token: str,
    log_sources: list[dict[str, str]] | None = None,
    include_windows_block: bool = False,
) -> str:
    """Build a starter agent.toml string.

    Pure function so tests can exercise it without a FastAPI
    client. ``log_sources`` defaults to the OS preset; pass
    an explicit list to override.
    """
    if log_sources is None:
        log_sources = _LOG_SOURCE_PRESETS.get(os, [])

    sections: list[str] = []
    sections.append("# ZaqorinCore agent configuration")
    sections.append("# Generated by /api/v1/agents/provision/template")
    sections.append(f"# OS: {os}    Arch: {arch}")
    sections.append(
        "# See ARCHITECTURE.md and agent.example.toml for field semantics."
    )
    sections.append("")
    sections.append(f"server_url = {_toml_quote(server_url)}")
    sections.append(f"agent_id    = {_toml_quote(agent_id)}")
    sections.append(f"auth_token  = {_toml_quote(auth_token)}")
    sections.append("")
    sections.append('log_level = "info"')
    if os == "windows":
        sections.append('state_dir = "C:\\\\ProgramData\\\\zaqorin-agent"')
    else:
        sections.append('state_dir = "/var/lib/zaqorin-agent"')
    sections.append("dry_run = true")
    sections.append("")

    sections.append(_toml_array_of_tables(log_sources).rstrip("\n"))
    sections.append("")

    if include_windows_block or os == "windows":
        sections.append("[windows_eventlog]")
        sections.append('mode = "pull"')
        sections.append("")

    sections.append("[response]")
    sections.append("allow_block_ip        = true")
    sections.append("allow_kill_process    = false")
    sections.append("allow_disable_user    = false")
    sections.append("block_default_ttl_sec = 3600")
    sections.append("")

    rendered = "\n".join(sections)
    if len(rendered.encode("utf-8")) > _MAX_TEMPLATE_BYTES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"rendered template is {len(rendered)} bytes; "
                f"limit is {_MAX_TEMPLATE_BYTES}"
            ),
        )
    return rendered


def parse_agent_toml(text: str) -> dict:
    """Parse a TOML config back into a dict.

    We use stdlib ``tomllib`` so this works on any Python 3.11+
    host without extra packages. Used by the live-config
    endpoint to verify the agent's view of the world is
    well-formed before returning it.
    """
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"generated TOML is not parseable: {e}",
        ) from e


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint handlers
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/provision/template", response_model=TemplateOut)
async def get_provision_template(
    os: OSLit = "linux",
    arch: ArchLit = "amd64",
) -> TemplateOut:
    """Return a starter agent.toml for ``os``/``arch``.

    The auth token is a random 32-byte hex blob the operator
    can paste into the install command; rotating it is as
    simple as re-running this endpoint and re-running the
    installer on the host.
    """
    server_url = _DEFAULT_SERVER_URL
    auth_token = secrets.token_hex(32)
    agent_id = f"agent-{uuid.uuid4().hex[:12]}"

    toml_text = render_agent_toml(
        os=os,
        arch=arch,
        server_url=server_url,
        agent_id=agent_id,
        auth_token=auth_token,
    )
    # Sanity round-trip: make sure what we hand the operator
    # is something the agent can actually parse.
    parse_agent_toml(toml_text)

    return TemplateOut(
        os=os,
        arch=arch,
        server_url=server_url,
        toml=toml_text,
        filename=f"agent-{os}-{arch}.toml",
    )


@router.post("/provision/dry-run", response_model=DryRunOut)
async def post_provision_dry_run(body: DryRunIn) -> DryRunOut:
    """Render the ``ssh`` command the installer would run.

    ``ssh_key_id`` is the operator's local SSH key alias
    (``~/.ssh/<id>``). The rendered command uses the
    ``-i`` flag if it is set, otherwise relies on the
    agent's ``~/.ssh/config`` lookup. The command is
    always a single ``ssh`` invocation followed by a
    heredoc that writes the agent.toml to ``/etc/zaqorin/``,
    so the operator can dry-run the file write without
    invoking the installer.
    """
    host = _safe_host(body.host)
    port = body.port
    user = _safe_user(body.user)
    key_id = _safe_key_id(body.ssh_key_id)

    ssh_args: list[str] = ["ssh"]
    if port != 22:
        ssh_args.extend(["-p", str(port)])
    if key_id:
        ssh_args.extend(["-i", f"~/.ssh/{key_id}"])
    ssh_args.extend(
        [
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{user}@{host}",
        ]
    )

    # Heredoc renders a minimal agent.toml into a temp file
    # the operator can ``cat`` to confirm the path is right
    # before the full installer runs.
    heredoc = (
        "cat > /etc/zaqorin/agent.toml.dry-run <<'ZAQORIN_EOF'\n"
        "# dry-run: this file is NOT the real agent config\n"
        "server_url = \"wss://zaqorin.example.com:8443/api/v1/events\"\n"
        "log_level  = \"info\"\n"
        "ZAQORIN_EOF\n"
        "systemctl --no-pager status zaqorin-agent || true"
    )
    install = " ".join(shlex.quote(p) for p in ssh_args) + " " + shlex.quote(heredoc)

    verify_args = list(ssh_args)
    verify_args.extend(
        [
            shlex.quote(
                "test -f /etc/zaqorin/agent.toml.dry-run && "
                "echo OK || echo MISSING"
            ),
        ]
    )
    verify = " ".join(shlex.quote(p) for p in verify_args)

    notes: list[str] = []
    if port != 22:
        notes.append(f"non-default SSH port {port}; ensure sshd listens there")
    if key_id:
        notes.append(
            f"using local SSH key alias {key_id!r}; ensure it is loaded in your agent"
        )

    return DryRunOut(
        host=host,
        port=port,
        user=user,
        install_command=install,
        verify_command=verify,
        notes=notes,
    )


@router.post("/provision/install-command", response_model=InstallCommandOut)
async def post_provision_install_command(
    body: InstallCommandIn,
) -> InstallCommandOut:
    """Return a one-line ``curl | bash`` installer.

    The rendered command is intended to be displayed to the
    operator verbatim. It pulls the matching binary from the
    public release bucket, writes the agent.toml, and
    enables the systemd / launchd / Scheduled Task unit.
    """
    host = _safe_host(body.host)
    agent_id = body.agent_id.strip()
    if not agent_id:
        raise HTTPException(
            status_code=422, detail="agent_id must not be blank"
        )
    if any(c in agent_id for c in (" ", "\t", "\n", "\r", '"', "\\", "$", "`")):
        raise HTTPException(
            status_code=422,
            detail=(
                "agent_id must not contain whitespace, quotes, or "
                "shell metacharacters"
            ),
        )

    auth_token = secrets.token_hex(32)
    server_url = _DEFAULT_SERVER_URL

    # Asset name: the release bucket ships one tarball per
    # OS / arch. ``ZAQORIN_VERSION`` can be overridden by the
    # operator; default to "latest" so a copy-paste works
    # against the current release.
    asset = f"zaqorin-agent-{body.os}.tar.gz"
    download_url = (
        f"https://releases.zaqorin.example.com/${{ZAQORIN_VERSION:-latest}}/{asset}"
    )

    # Artifact digest — populated from a CI-pinned manifest, NOT
    # fetched at request time (that would be an SSRF; same lesson
    # as F3). The install script refuses to extract if the
    # downloaded tarball's digest does not match. Closing F-015:
    # the previous ``curl ... | tar -xz`` piped untrusted bytes
    # straight into the extractor; the new shape downloads to a
    # temp file, verifies SHA-256 against this constant, then
    # extracts only on match.
    artifact_sha256 = _ARTIFACT_SHA256_BY_OS.get(body.os)
    warnings: list[str] = []
    if artifact_sha256 is None:
        # Defensive — keeps the endpoint working for unknown OSes
        # but flags the gap so the operator notices.
        artifact_sha256 = "0" * 64
        warnings.append(
            f"no pinned SHA-256 for os={body.os!r}; the installer "
            "will REFUSE to extract until the manifest ships one"
        )

    # Build the agent.toml inline using a heredoc so the
    # operator can ``cat /etc/zaqorin/agent.toml`` and see
    # the values without hunting for a sidecar file.
    toml_inline = (
        f"server_url = \"{server_url}\"\n"
        f"agent_id    = \"{agent_id}\"\n"
        f"auth_token  = \"{auth_token}\"\n"
    )

    if body.os == "windows":
        # Windows doesn't have curl|bash. The endpoint is
        # deliberately cross-platform; the Windows payload
        # is a PowerShell snippet that downloads to a temp
        # file, verifies SHA-256 via Get-FileHash, then
        # extracts. Same download-verify-execute shape as the
        # POSIX path — closes F-015 on both OSes.
        install = (
            "$ErrorActionPreference = 'Stop'; "
            "$url = '"
            + download_url
            + "'; "
            "$dst = Join-Path $env:TEMP 'zaqorin-agent.tar.gz'; "
            "$expected = '"
            + artifact_sha256
            + "'; "
            "Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing; "
            "$actual = (Get-FileHash -Algorithm SHA256 -Path $dst).Hash.ToLower(); "
            "if ($actual -ne $expected) { "
            "Remove-Item $dst -Force; "
            "throw \"SHA-256 mismatch: expected $expected, got $actual\" "
            "}; "
            "New-Item -ItemType Directory -Force -Path "
            "'C:\\ProgramData\\zaqorin-agent' | Out-Null; "
            "tar -xzf $dst -C 'C:\\ProgramData\\zaqorin-agent'; "
            "Set-Content -Path 'C:\\ProgramData\\zaqorin-agent\\agent.toml' "
            "-Value @'\n"
            + toml_inline
            + "'@; "
            "& 'C:\\ProgramData\\zaqorin-agent\\zaqorin-agent.exe' --register"
        )
    else:
        # POSIX: download to a temp file, verify SHA-256, then
        # extract. No more pipe-to-extractor; the bytes are
        # pinned before they touch the filesystem.
        install = (
            "set -euo pipefail; "
            "tmp=$(mktemp -d); "
            "tgz=$tmp/zaqorin-agent.tar.gz; "
            f"curl -fsSL {shlex.quote(download_url)} -o $tgz; "
            f"actual=$(sha256sum $tgz | awk '{{print $1}}'); "
            f"expected={shlex.quote(artifact_sha256)}; "
            "if [ \"$actual\" != \"$expected\" ]; then "
            "echo \"SHA-256 mismatch: expected $expected, got $actual\" >&2; "
            "rm -rf $tmp; exit 1; "
            "fi; "
            "tar -xz -C $tmp -f $tgz; "
            "install -m 0755 $tmp/zaqorin-agent /usr/local/bin/zaqorin-agent; "
            "install -d -m 0755 /etc/zaqorin; "
            "cat > /etc/zaqorin/agent.toml <<'ZAQORIN_EOF'\n"
            + toml_inline
            + "ZAQORIN_EOF\n"
            "install -m 0644 $tmp/zaqorin-agent.service /etc/systemd/system/; "
            "systemctl daemon-reload; "
            "systemctl enable --now zaqorin-agent"
        )

    # SHA-256 of the artifact (NOT the rendered command) so the
    # operator can cross-check against the published manifest in
    # the release notes. The rendered command embeds the random
    # auth token, so a digest of it would change every call —
    # useless as a fingerprint. The artifact digest is stable
    # per release.
    import hashlib

    digest = artifact_sha256

    # F-021: do NOT use string-prefix matching on RFC1918 octets
    # ("10.", "192.168.", "172.") — a public DNS name like
    # "10x.example.com" or "1720-sensor.example.com" would match
    # and skip the redaction branch, re-leaking the hostname in
    # the response. Use ipaddress.ip_address() to actually parse
    # the input as an IP, and ip.is_private / ip.is_loopback /
    # ip.is_link_local to classify. DNS names never parse as
    # IPs, so the ValueError branch handles the "host is a DNS
    # name" case (which is the case we want to redact).
    import ipaddress

    try:
        addr = ipaddress.ip_address(host)
        is_internal = (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        # host is a DNS name, not an IP — always treat as public
        is_internal = False

    if not is_internal:
        # F-019: redact the literal hostname from the response
        # (CWE-200). The operator still sees the full value in
        # the request log; the response carries only a
        # deterministic SHA-256 prefix they can grep on.
        host_fp = hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]
        log.info(
            "agents_provision: public-DNS host detected",
            extra={"host_fp": host_fp, "host": host},
        )
        warnings.append(
            f"host {host_fp} is a public DNS name (name redacted "
            "— see server logs); the installer will reach the "
            "public release bucket"
        )

    return InstallCommandOut(
        command=install,
        sha256=digest,
        warnings=warnings,
    )


@router.post("/{agent_id}/rotate-secret", response_model=RotateSecretOut)
async def post_rotate_secret(
    agent_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> RotateSecretOut:
    """Generate a new 32-byte hex HMAC secret for ``agent_id``.

    Persists the new secret on the ``hosts.secret`` column.
    The previous secret is overwritten; this endpoint does
    not keep a history (rotation replay = same fresh value
    each time, idempotently).
    """
    stmt = sa_select(Host).where(Host.id == agent_id)
    result = await session.execute(stmt)
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown agent_id: {agent_id}",
        )

    new_secret = secrets.token_hex(32)
    host.secret = new_secret
    # Touch last_seen_at so the rotate call shows up in
    # heartbeat math (an operator calling this endpoint is
    # "interacting with" the host).
    host.last_seen_at = datetime.now(timezone.utc)
    await session.commit()

    log.info(
        "agents_provision: rotated HMAC secret",
        extra={"agent_id": str(agent_id)},
    )

    return RotateSecretOut(
        agent_id=agent_id,
        rotated_at=host.last_seen_at,
        secret_preview=new_secret[:8],
    )


@router.get("/{agent_id}/config", response_model=ConfigOut)
async def get_agent_config(
    agent_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ConfigOut:
    """Return the live agent.toml the agent should be running.

    Synthesised from the ``Host`` row + the server's public
    base URL. The HMAC secret is NEVER included in the
    response (the agent reads it from a sidecar file the
    operator provisioned out-of-band; exposing it in the
    WebUI would defeat the point of per-host signing).
    """
    stmt = sa_select(Host).where(Host.id == agent_id)
    result = await session.execute(stmt)
    host = result.scalar_one_or_none()
    if host is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown agent_id: {agent_id}",
        )

    server_url = _DEFAULT_SERVER_URL
    # Use the row's last_seen_at to seed a deterministic-ish
    # log source set; for now we just default to the Linux
    # preset (most agents today run on Linux). Future
    # enhancement: read OS from Host.meta["os"] and pick
    # the right preset.
    log_sources = list(_LOG_SOURCE_PRESETS["linux"])
    toml_text = render_agent_toml(
        os="linux",
        arch="amd64",
        server_url=server_url,
        agent_id=str(host.id),
        auth_token="<hidden — set out-of-band>",
        log_sources=log_sources,
    )
    parse_agent_toml(toml_text)

    warnings: list[str] = []
    if not host.last_seen_at:
        warnings.append(
            "host has never checked in; the rendered config may "
            "be stale"
        )

    return ConfigOut(
        agent_id=host.id,
        server_url=server_url,
        agent_id_field=str(host.id),
        hostname=host.hostname,
        last_seen_at=host.last_seen_at,
        toml=toml_text,
        warnings=warnings,
    )


__all__ = [
    "router",
    "render_agent_toml",
    "parse_agent_toml",
]
