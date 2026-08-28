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

from .base import Detector
from .ssh_bruteforce import DETECTOR as _ssh_bruteforce

BUILTIN_DETECTORS: list[Detector] = [
    _ssh_bruteforce,
]


__all__ = ["BUILTIN_DETECTORS"]
