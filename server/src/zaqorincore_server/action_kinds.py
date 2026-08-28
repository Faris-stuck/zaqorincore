"""Action kind registry.

Phase 5 ships 9 action kinds per ADR-003. Each kind is defined here with
its target shape, validation, and default TTL. The dispatcher consults this
registry to validate a request before signing a COMMAND frame.

Adding a new action kind:
1. Add a Kind entry below.
2. Implement the executor in agent/internal/response/kinds/<kind>.go.
3. Register the executor in agent/internal/response/registry.go.
4. Add a test in server/tests/test_action_kinds.py.
5. Add the kind to the relevant ModeProfile in deployment.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


# Target shapes per kind:
#   "ipv4"      - dotted-quad IPv4 address
#   "ipv4_cidr" - IPv4 CIDR (e.g. 10.0.0.0/24)
#   "pid"       - process id (positive integer as string)
#   "path"      - absolute filesystem path
#   "user"      - username (alphanumeric, underscore, hyphen)
#   "session"   - session/credential identifier (opaque string)
#   "url"       - HTTP(S) URL
#   "host"      - hostname or agent_id
TargetShape = Literal[
    "ipv4", "ipv4_cidr", "pid", "path", "user", "session", "url", "host"
]


@dataclass(frozen=True)
class Kind:
    """An action kind definition."""

    name: str
    target_shape: TargetShape
    default_ttl_sec: int
    description: str
    requires_host_opt_in: bool


# Order matters: this is the order the dashboard lists them.
KINDS: dict[str, Kind] = {
    "block_ip": Kind(
        name="block_ip",
        target_shape="ipv4",
        default_ttl_sec=3600,
        description="Drop all traffic from this source IP via nftables.",
        requires_host_opt_in=True,
    ),
    "tarpit_ip": Kind(
        name="tarpit_ip",
        target_shape="ipv4",
        default_ttl_sec=1800,
        description="Accept connections from this IP but throttle reads to a trickle.",
        requires_host_opt_in=True,
    ),
    "canary_alert": Kind(
        name="canary_alert",
        target_shape="path",
        default_ttl_sec=0,  # 0 = no TTL, canary persists
        description="Alert when this canary file/path is touched. Zero false positives.",
        requires_host_opt_in=False,
    ),
    "isolate_host": Kind(
        name="isolate_host",
        target_shape="host",
        default_ttl_sec=900,
        description="Block all network egress from this host (kill switch).",
        requires_host_opt_in=True,
    ),
    "kill_process": Kind(
        name="kill_process",
        target_shape="pid",
        default_ttl_sec=0,
        description="Send SIGKILL to the offending process (cgroup-scoped).",
        requires_host_opt_in=True,
    ),
    "quarantine_file": Kind(
        name="quarantine_file",
        target_shape="path",
        default_ttl_sec=0,
        description="chmod 000 the file and move it to the evidence vault.",
        requires_host_opt_in=True,
    ),
    "revoke_session": Kind(
        name="revoke_session",
        target_shape="session",
        default_ttl_sec=86400,
        description="Invalidate the session/credential and force re-auth.",
        requires_host_opt_in=True,
    ),
    "webhook_soar": Kind(
        name="webhook_soar",
        target_shape="url",
        default_ttl_sec=0,
        description="POST a signed event to a SOAR endpoint. Action lives in the SOAR.",
        requires_host_opt_in=False,
    ),
    "evidence_capture": Kind(
        name="evidence_capture",
        target_shape="host",
        default_ttl_sec=0,
        description="Capture logs/process tree/network state into the evidence vault.",
        requires_host_opt_in=False,
    ),
}


def is_valid_kind(name: str) -> bool:
    """Return True if `name` is a registered action kind."""
    return name in KINDS


def get_kind(name: str) -> Kind:
    """Return the Kind for `name` or raise ValueError."""
    if not is_valid_kind(name):
        valid = ", ".join(KINDS.keys())
        raise ValueError(f"unknown action kind {name!r}; valid: {valid}")
    return KINDS[name]


def list_kinds() -> list[str]:
    """Return all registered kind names in declaration order."""
    return list(KINDS.keys())


def validate_target(kind_name: str, target: str) -> None:
    """Raise ValueError if `target` is malformed for `kind_name`.

    This is a coarse format check, not a semantic check. For example
    we don't verify that an IPv4 address is actually routable.
    """
    kind = get_kind(kind_name)
    shape = kind.target_shape

    if shape == "ipv4":
        parts = target.split(".")
        if len(parts) != 4:
            raise ValueError(
                f"target {target!r} is not a valid IPv4 address (expected a.b.c.d)"
            )
        for part in parts:
            try:
                n = int(part)
            except ValueError:
                raise ValueError(
                    f"target {target!r} is not a valid IPv4 address (non-numeric octet {part!r})"
                )
            if not 0 <= n <= 255:
                raise ValueError(
                    f"target {target!r} is not a valid IPv4 address (octet {n} out of range)"
                )
        return

    if shape == "ipv4_cidr":
        if "/" not in target:
            raise ValueError(
                f"target {target!r} is not a valid CIDR (expected a.b.c.d/n)"
            )
        ip, _, prefix = target.partition("/")
        # Validate the IP portion directly without recursing into the
        # kind's own validator (which expects an ipv4, not a cidr).
        parts = ip.split(".")
        if len(parts) != 4:
            raise ValueError(
                f"target {target!r} is not a valid CIDR (IP portion not 4 octets)"
            )
        for part in parts:
            try:
                n = int(part)
            except ValueError:
                raise ValueError(
                    f"target {target!r} is not a valid CIDR (non-numeric octet {part!r})"
                )
            if not 0 <= n <= 255:
                raise ValueError(
                    f"target {target!r} is not a valid CIDR (octet {n} out of range)"
                )
        try:
            n = int(prefix)
        except ValueError:
            raise ValueError(
                f"target {target!r} is not a valid CIDR (non-numeric prefix {prefix!r})"
            )
        if not 0 <= n <= 32:
            raise ValueError(
                f"target {target!r} is not a valid CIDR (prefix {n} out of range)"
            )
        return

    if shape == "pid":
        try:
            n = int(target)
        except ValueError:
            raise ValueError(
                f"target {target!r} is not a valid PID (non-numeric)"
            )
        if n <= 0:
            raise ValueError(
                f"target {target!r} is not a valid PID (must be > 0)"
            )
        return

    if shape == "path":
        if not target.startswith("/"):
            raise ValueError(
                f"target {target!r} is not an absolute path (must start with /)"
            )
        return

    if shape == "user":
        if not target:
            raise ValueError("target username is empty")
        if not all(c.isalnum() or c in ("_", "-", ".") for c in target):
            raise ValueError(
                f"target username {target!r} contains illegal characters"
            )
        return

    if shape in ("session", "host", "url"):
        # Opaque strings; we just require non-empty.
        if not target:
            raise ValueError(f"target for kind {kind_name!r} is empty")
        return

    # Exhaustiveness guard. If a new shape is added to TargetShape
    # without a case above, this raises.
    raise ValueError(f"unknown target shape {shape!r} for kind {kind_name!r}")
