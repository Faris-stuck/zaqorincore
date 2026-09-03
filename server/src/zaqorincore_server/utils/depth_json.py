"""F-027: depth-limited JSON decoder.

Extracted from ``ingest_cloudflare.py`` so the unit tests can
import the class without dragging in the FastAPI app surface
(which fails its parameter-less dependency check at import time
in the test environment — a pre-existing condition, not a
regression introduced by the F-027 fix).

The class is the same one used by ``ingest_cloudflare`` at
runtime; only the import path is different.
"""

from __future__ import annotations

import json
from typing import Any

MAX_JSON_DEPTH = 32


class DepthLimitedDecoder(json.JSONDecoder):
    """``json.JSONDecoder`` that raises :class:`ValueError` on too-deep
    nesting instead of blowing the recursion limit (CWE-400 / F-027).

    Tracks nesting depth by a linear pass over the source string
    counting unmatched ``[`` / ``{`` (and ``]`` / ``}``) characters,
    correctly handling strings and escape sequences.
    """

    def __init__(
        self,
        *args: Any,
        max_depth: int = MAX_JSON_DEPTH,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._max_depth = max_depth

    def raw_decode(  # type: ignore[override]
        self,
        s: str,
        idx: int = 0,
    ) -> tuple[Any, int]:
        self._check_depth(s, idx)
        obj, end = super().raw_decode(s, idx)
        return obj, end

    def decode(self, s: str) -> Any:  # type: ignore[override]
        self._check_depth(s, 0)
        return super().decode(s)

    def _check_depth(self, s: str, idx: int) -> None:
        """Approximate nesting depth by counting the max stack of
        ``[`` / ``{`` that opens without the matching close. Linear
        pass — O(n) and constant memory, no recursion."""
        depth = 0
        in_string = False
        escape = False
        i = idx
        n = len(s)
        while i < n:
            ch = s[i]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch in "[{":
                    depth += 1
                    if depth > self._max_depth:
                        raise ValueError(
                            f"JSON nesting depth exceeds {self._max_depth}"
                        )
                elif ch in "]}":
                    depth -= 1
            i += 1


# Singleton for hot-path reuse.
_default_decoder = DepthLimitedDecoder()


def safe_loads(s: str) -> Any:
    """Drop-in replacement for ``json.loads`` that caps nesting depth."""
    return _default_decoder.decode(s)
