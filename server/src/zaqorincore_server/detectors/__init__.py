"""Detector registry.

BUILTIN_DETECTORS is the ordered list of detectors the runner
calls for every event. Order is mostly cosmetic — detectors
should be independent of one another — but it does influence
which one wins if two detectors emit alerts with the same
`dedup_key` in the same `cooldown_sec` window (the first wins;
the second is dropped).

Adding a new detector:
1. Create `detectors/<name>.py` with a module-level `DETECTOR`
   instance that satisfies the `Detector` protocol.
2. Import it here and append to `BUILTIN_DETECTORS`.
3. Restart the server. No DB migration.
"""

from __future__ import annotations

from .auth_anomaly import DETECTOR as _auth_anomaly
from .base import Detector
from .dns_tunnel import DETECTOR as _dns_tunnel
from .port_scan import DETECTOR as _port_scan
from .ssh_bruteforce import DETECTOR as _ssh_bruteforce
from .web_attack import DETECTOR as _web_attack

BUILTIN_DETECTORS: list[Detector] = [
    _ssh_bruteforce,
    _port_scan,
    _web_attack,
    _dns_tunnel,
    _auth_anomaly,
]


__all__ = ["BUILTIN_DETECTORS"]
