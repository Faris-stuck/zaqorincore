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


def _parse_ipv4(target: str) -> tuple[int, int, int, int]:
    """Parse a dotted-quad IPv4 address into 4 octets.

    Raises ValueError on malformed input. Used by both ``ipv4`` and
    ``ipv4_cidr`` validators below.
    """
    parts = target.split(".")
    if len(parts) != 4:
        raise ValueError(
            f"target {target!r} is not a valid IPv4 address (expected a.b.c.d)"
        )
    octets: list[int] = []
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
        octets.append(n)
    return octets[0], octets[1], octets[2], octets[3]


def _ip_to_int(o1: int, o2: int, o3: int, o4: int) -> int:
    return (o1 << 24) | (o2 << 16) | (o3 << 8) | o4


# SECURITY (F9): Targets that are syntactically valid but
# semantically catastrophic. A typo or buggy rule with one of
# these will block the entire network (0.0.0.0/0), the host
# itself (127.0.0.0/8), the broadcast address, or the multicast
# range. We refuse to dispatch them at all. Operators who
# really need to override can flip ZAQORIN_ALLOW_DANGEROUS_TARGETS=1
# at startup (the env var is read here, not per-call, so it's
# a deliberate operator action and not a request-time flag).
def _allow_dangerous() -> bool:
    import os as _os

    return _os.environ.get("ZAQORIN_ALLOW_DANGEROUS_TARGETS", "") == "1"


# Single-host loopback (127.0.0.0/8): blocking one of these kills
# the host's own loopback stack. Range covered: 127.0.0.0 .. 127.255.255.255.
_LOOPBACK_LO = _ip_to_int(127, 0, 0, 0)
_LOOPBACK_HI = _ip_to_int(127, 255, 255, 255)
# Multicast (224.0.0.0/4): 224.0.0.0 .. 239.255.255.255.
_MULTICAST_LO = _ip_to_int(224, 0, 0, 0)
_MULTICAST_HI = _ip_to_int(239, 255, 255, 255)
# Reserved / not-routable / dangerous ranges we refuse to dispatch
# block_ip against without the explicit operator override.
_DENY_RANGES: tuple[tuple[str, str, int, int], ...] = (
    ("loopback", "127.0.0.0/8", _LOOPBACK_LO, _LOOPBACK_HI),
    ("multicast", "224.0.0.0/4", _MULTICAST_LO, _MULTICAST_HI),
)


def _check_dangerous_single(addr: int) -> None:
    """Raise if the address falls in a deny range."""
    if _allow_dangerous():
        return
    if addr == 0:
        raise ValueError(
            "target 0.0.0.0 is the unspecified address; refusing to "
            "dispatch (set ZAQORIN_ALLOW_DANGEROUS_TARGETS=1 to override)"
        )
    if addr == _ip_to_int(255, 255, 255, 255):
        raise ValueError(
            "target 255.255.255.255 is the IPv4 broadcast address; "
            "refusing to dispatch (set ZAQORIN_ALLOW_DANGEROUS_TARGETS=1 "
            "to override)"
        )
    for label, cidr, lo, hi in _DENY_RANGES:
        if lo <= addr <= hi:
            raise ValueError(
                f"target falls in {label} range {cidr}; refusing to "
                f"dispatch (set ZAQORIN_ALLOW_DANGEROUS_TARGETS=1 to override)"
            )


def _check_dangerous_cidr(addr: int, prefix: int) -> None:
    """Raise if the CIDR would deny catastrophic scope.

    A CIDR with prefix <= 8 covers at least a /8 (16M addresses).
    A CIDR with prefix == 0 covers everything (0.0.0.0/0). Either
    of these is almost certainly an operator mistake and we refuse
    unless the override env is set.
    """
    if _allow_dangerous():
        return
    if prefix == 0:
        raise ValueError(
            "target CIDR has /0 prefix (covers the entire IPv4 "
            "internet); refusing to dispatch (set "
            "ZAQORIN_ALLOW_DANGEROUS_TARGETS=1 to override)"
        )
    if prefix <= 8:
        raise ValueError(
            f"target CIDR has /{prefix} prefix (covers "
            f"{1 << (32 - prefix):,} addresses); refusing to dispatch "
            "(set ZAQORIN_ALLOW_DANGEROUS_TARGETS=1 to override)"
        )
    # Also check that the network address itself doesn't fall in a
    # deny range — e.g. 127.0.0.0/24 still lands in loopback.
    for label, cidr, lo, hi in _DENY_RANGES:
        if lo <= addr <= hi:
            raise ValueError(
                f"target CIDR network address falls in {label} "
                f"range {cidr}; refusing to dispatch (set "
                "ZAQORIN_ALLOW_DANGEROUS_TARGETS=1 to override)"
            )


def validate_target(kind_name: str, target: str) -> None:
    """Raise ValueError if `target` is malformed for `kind_name`.

    The shape check is coarse (well-formed IPv4, well-formed CIDR,
    etc.). After the shape check, ``ipv4`` and ``ipv4_cidr`` also
    undergo a semantic deny-list (F9): we refuse to dispatch
    block_ip against the loopback range, the multicast range, the
    unspecified address (0.0.0.0), the broadcast address
    (255.255.255.255), or any CIDR with prefix <= 8 unless the
    operator has set ``ZAQORIN_ALLOW_DANGEROUS_TARGETS=1``.

    This is intentionally stricter than a format-only check so
    that a buggy rule with ``target: "0.0.0.0"`` cannot ship to
    an agent and accidentally blackhole traffic.
    """
    kind = get_kind(kind_name)
    shape = kind.target_shape

    if shape == "ipv4":
        o1, o2, o3, o4 = _parse_ipv4(target)
        _check_dangerous_single(_ip_to_int(o1, o2, o3, o4))
        return

    if shape == "ipv4_cidr":
        if "/" not in target:
            raise ValueError(
                f"target {target!r} is not a valid CIDR (expected a.b.c.d/n)"
            )
        ip, _, prefix = target.partition("/")
        o1, o2, o3, o4 = _parse_ipv4(ip)
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
        _check_dangerous_cidr(_ip_to_int(o1, o2, o3, o4), n)
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
