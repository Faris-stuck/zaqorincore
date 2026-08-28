"""SOAR backend configuration loader (ADR-008 / v1.3.0).

The TOML file at `server/config/soar.toml` (or the path given
by the ZAQORIN_SOAR_CONFIG env var) describes which backends
are enabled and how each is configured.

Why not pydantic-settings? The whole point of SOAR is that
operators wire it into the system they already use; one
operator may run 6 backends, another may run 0. Keeping the
config in a separate file (rather than 30 env vars) means
they can review, version-control, and hot-reload the SOAR
layer without touching the rest of the server config.

The shape (mirrors `soar.toml.example`):

    [soar]
    enabled = true
    poll_sec = 2.0
    queue_max = 1000
    dead_letter_dir = "var/soar/dead-letter"
    public_base_url = "https://zaqorin.example.com"

    [backends.generic_webhook]
    enabled = true
    url = "https://my-target.example.com/hook"
    auth_header = "Bearer ..."
    method = "POST"
    content_type = "application/json"
    template = '{ "alert_id": "{{ alert.id }}", ... }'
    cooldown_sec = 60
    severity_min = "medium"
    tags_filter = []
    max_retries = 5

    [backends.slack]
    enabled = false
    url = "https://hooks.slack.com/services/..."
    cooldown_sec = 60
    severity_min = "medium"
    tags_filter = []
    max_retries = 5

    ...

Unknown / missing backends: not loaded. `enabled = false`:
loaded but skipped at dispatch time. Unknown keys in a
backend block: ignored (forward-compat).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# Default config path. Resolved relative to the server package
# directory at runtime (see `_default_config_path`).
_DEFAULT_PATH = "config/soar.toml"

# All six backends shipped in v1.3.0. Slice 1 (scaffold)
# already registered them; the real config keys match these
# names. Adding a seventh later means just adding it here and
# shipping a backend in `soar/backends/<name>.py`.
KNOWN_BACKENDS = (
    "generic_webhook",
    "slack",
    "discord",
    "pagerduty",
    "thehive",
    "jira",
)

# Severity ordering used by `severity_min`. Critical > High >
# Medium > Low > Info. A backend with severity_min="medium"
# fires for medium, high, and critical; it skips low and info.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Sane defaults so an empty `[backends.X]` block doesn't crash
# the worker. These are conservative — they err on the side
# of "do nothing" so a misconfigured file is silent, not
# noisy.
_DEFAULTS = {
    "enabled": False,
    "cooldown_sec": 60,
    "severity_min": "low",
    "tags_filter": [],
    "max_retries": 5,
    "timeout_sec": 10.0,
}


@dataclass(frozen=True)
class BackendConfig:
    """Per-backend configuration block."""

    name: str
    enabled: bool
    cooldown_sec: int
    severity_min: str
    tags_filter: list[str]
    max_retries: int
    timeout_sec: float
    # Free-form backend-specific keys (url, auth_header,
    # template, slack URL, etc.). Each backend reads the
    # subset it cares about.
    extra: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class SoarConfig:
    """Top-level SOAR config block."""

    enabled: bool
    poll_sec: float
    queue_max: int
    dead_letter_dir: str
    public_base_url: str
    backends: dict[str, BackendConfig]


def _default_config_path() -> Path:
    """Resolve the default config path.

    Looks first in the current working directory, then next to
    the package. The env var ZAQORIN_SOAR_CONFIG overrides
    both.
    """
    env = os.environ.get("ZAQORIN_SOAR_CONFIG")
    if env:
        return Path(env)
    cwd = Path.cwd() / _DEFAULT_PATH
    if cwd.exists():
        return cwd
    pkg = Path(__file__).resolve().parent.parent.parent.parent / _DEFAULT_PATH
    return pkg


def _coerce_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _coerce_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _coerce_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(x) for x in value]
    return []


def load_config(path: Path | None = None) -> SoarConfig:
    """Load SOAR config from TOML. Returns defaults on a
    missing or invalid file (with backends disabled).

    This is intentionally tolerant: the SOAR layer is
    optional. If the operator hasn't configured it, the worker
    simply doesn't run, and the rest of the server is
    unaffected.
    """
    cfg_path = path or _default_config_path()
    if not cfg_path.exists():
        return SoarConfig(
            enabled=False,
            poll_sec=2.0,
            queue_max=1000,
            dead_letter_dir="var/soar/dead-letter",
            public_base_url="",
            backends={},
        )

    with cfg_path.open("rb") as fh:
        raw = tomllib.load(fh)

    soar_block = raw.get("soar", {}) if isinstance(raw, dict) else {}
    enabled = bool(soar_block.get("enabled", False))
    poll_sec = _coerce_float(soar_block.get("poll_sec", 2.0), 2.0)
    queue_max = _coerce_int(soar_block.get("queue_max", 1000), 1000)
    dead_letter_dir = str(
        soar_block.get("dead_letter_dir", "var/soar/dead-letter")
    )
    public_base_url = str(soar_block.get("public_base_url", "")).rstrip("/")

    backends: dict[str, BackendConfig] = {}
    backends_raw = raw.get("backends", {}) if isinstance(raw, dict) else {}
    if not isinstance(backends_raw, dict):
        backends_raw = {}

    for name, block in backends_raw.items():
        if name not in KNOWN_BACKENDS:
            # Unknown backend name in the file. We surface a
            # clear error at startup instead of silently
            # dropping it.
            raise ValueError(
                f"soar.toml: unknown backend {name!r} "
                f"(known: {', '.join(KNOWN_BACKENDS)})"
            )
        if not isinstance(block, dict):
            continue
        bc_enabled = bool(block.get("enabled", _DEFAULTS["enabled"]))
        bc_cooldown = _coerce_int(
            block.get("cooldown_sec", _DEFAULTS["cooldown_sec"]),
            _DEFAULTS["cooldown_sec"],
        )
        bc_sev_min = str(
            block.get("severity_min", _DEFAULTS["severity_min"])
        )
        if bc_sev_min not in SEVERITY_ORDER:
            bc_sev_min = _DEFAULTS["severity_min"]
        bc_tags = _coerce_list(
            block.get("tags_filter", _DEFAULTS["tags_filter"])
        )
        bc_max_retries = _coerce_int(
            block.get("max_retries", _DEFAULTS["max_retries"]),
            _DEFAULTS["max_retries"],
        )
        bc_timeout = _coerce_float(
            block.get("timeout_sec", _DEFAULTS["timeout_sec"]),
            _DEFAULTS["timeout_sec"],
        )
        # Reserved keys (handled above) are not passed to the
        # backend in `extra`. Everything else is.
        reserved = {
            "enabled",
            "cooldown_sec",
            "severity_min",
            "tags_filter",
            "max_retries",
            "timeout_sec",
        }
        extra = {k: v for k, v in block.items() if k not in reserved}
        backends[name] = BackendConfig(
            name=name,
            enabled=bc_enabled,
            cooldown_sec=max(0, bc_cooldown),
            severity_min=bc_sev_min,
            tags_filter=bc_tags,
            max_retries=max(0, bc_max_retries),
            timeout_sec=max(1.0, bc_timeout),
            extra=extra,
        )

    return SoarConfig(
        enabled=enabled,
        poll_sec=max(0.1, poll_sec),
        queue_max=max(1, queue_max),
        dead_letter_dir=dead_letter_dir,
        public_base_url=public_base_url,
        backends=backends,
    )


def severity_meets(actual: str, minimum: str) -> bool:
    """Return True if `actual` severity is at or above
    `minimum`. Unknown severities map to 0 (so they never
    match a positive minimum)."""
    a = SEVERITY_ORDER.get(actual.lower(), 0)
    m = SEVERITY_ORDER.get(minimum.lower(), 0)
    return a >= m


__all__ = [
    "BackendConfig",
    "KNOWN_BACKENDS",
    "SEVERITY_ORDER",
    "SoarConfig",
    "load_config",
    "severity_meets",
]
