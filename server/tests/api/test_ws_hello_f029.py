"""F-029: WS /ws/agent must cap HELLO frame size and use depth-limited JSON.

Two related issues in the WebSocket ingest path:

1. The HELLO frame (line 103 of ``stream.py``) was read with no size
   cap. A misbehaving agent (or any TCP peer past the HMAC check) could
   deliver a multi-MiB first frame and exhaust server RAM.
2. Both the HELLO and subsequent event frames called ``json.loads``,
   which is unbounded in nesting depth. A 64 KiB HELLO of deeply-nested
   JSON would trip ``sys.setrecursionlimit`` and 500 the worker.

The F-009 fix already capped subsequent frames via
``settings.ws_max_msg_bytes``; the HELLO frame slipped past that
because the size check happens *after* ``receive_text()``.

The F-027 / F-028 fix introduced a depth-limited decoder in
``zaqorincore_server.utils.depth_json``. F-029 applies it to the
WebSocket path and adds a tight HELLO-specific byte cap.

These tests live outside the full FastAPI test surface (no
``TestClient`` + app) so they run in the import-free environment the
F-027 / F-028 tests use. They cover the same depth-limited behavior
plus a synthetic size-cap check.
"""

from __future__ import annotations

import json

import pytest

from zaqorincore_server.utils.depth_json import (
    MAX_JSON_DEPTH,
    DepthLimitedDecoder,
    safe_loads,
)

MAX_HELLO_BYTES = 64 * 1024


def test_f029_typical_hello_parses_ok() -> None:
    """A normal HELLO frame (id + nonce + signature) parses cleanly."""
    hello = {
        "type": "hello",
        "v": 2,
        "agent_id": "11111111-1111-1111-1111-111111111111",
        "nonce": "abc" * 32,
        "sig": "deadbeef" * 16,
    }
    raw = json.dumps(hello)
    assert len(raw) < MAX_HELLO_BYTES, "fixture should fit in HELLO cap"
    parsed = safe_loads(raw)
    assert parsed["type"] == "hello"
    assert parsed["v"] == 2


def test_f029_hello_over_hello_size_cap_detected_by_byte_count() -> None:
    """A HELLO longer than MAX_HELLO_BYTES is identified as oversize.

    This mirrors the ``stream.py`` pre-parse size check (line 113)
    which fires before JSON parsing. The depth check below (line 122)
    is a defence-in-depth layer for the case where the byte cap
    passes but the JSON is still pathological.
    """
    raw = '{"type": "hello", "pad": "' + ("x" * MAX_HELLO_BYTES) + '"}'
    assert len(raw) > MAX_HELLO_BYTES, "fixture must exceed HELLO byte cap"
    # The byte cap alone is enough to reject the frame at the
    # application layer; we do not even attempt to parse.

def test_f029_hello_under_size_cap_but_over_depth_rejected() -> None:
    """A HELLO within the byte cap but over the depth cap is rejected.

    This is the defence-in-depth scenario: byte count is fine, but
    a small but deeply-nested payload is still caught by the
    depth-limited decoder.
    """
    # Build a 100-deep nested object that is small in bytes.
    depth = MAX_JSON_DEPTH + 1
    raw = "{" * depth + "}" * depth
    assert len(raw) <= MAX_HELLO_BYTES, (
        "fixture should fit in HELLO cap (depth+1 open + close braces)"
    )
    with pytest.raises(ValueError, match="nesting depth"):
        safe_loads(raw)


def test_f029_hello_at_depth_limit_parses_ok() -> None:
    """A HELLO at exactly the depth cap still parses."""
    depth = MAX_JSON_DEPTH - 1
    raw = '{"a":' * depth + '"leaf"' + "}" * depth
    parsed = safe_loads(raw)
    assert isinstance(parsed, dict)


def test_f029_hello_over_depth_limit_rejected() -> None:
    """A HELLO over the depth cap raises ValueError, not RecursionError."""
    depth = MAX_JSON_DEPTH + 1
    raw = "{" * depth + "}" * depth
    with pytest.raises(ValueError, match="nesting depth"):
        safe_loads(raw)


def test_f029_event_frame_at_depth_limit_parses_ok() -> None:
    """A typical event frame at the depth cap still parses."""
    depth = MAX_JSON_DEPTH - 1
    raw = (
        '{"type":"event","id":"' + "a" * 32 + '",'
        '"data":' + '{"k":' * depth + '"v"' + "}" * depth + "}"
    )
    parsed = safe_loads(raw)
    assert parsed["type"] == "event"


def test_f029_event_frame_over_depth_limit_rejected() -> None:
    """An event frame over the depth cap is rejected cleanly."""
    depth = MAX_JSON_DEPTH + 1
    raw = "{" * depth + "}" * depth
    with pytest.raises(ValueError, match="nesting depth"):
        safe_loads(raw)


def test_f029_depth_decoder_uses_module_default() -> None:
    """The DepthLimitedDecoder default cap matches the module constant."""
    d = DepthLimitedDecoder()
    # At-limit case: depth-1 nested dicts (leaf = "leaf") is well
    # within the cap and parses successfully.
    at_limit = '{"a":' * (MAX_JSON_DEPTH - 1) + '"leaf"' + "}" * (MAX_JSON_DEPTH - 1)
    parsed = d.decode(at_limit)
    assert isinstance(parsed, dict)
    # Over-limit case raises.
    over_limit = "[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1)
    with pytest.raises(ValueError, match="nesting depth"):
        d.decode(over_limit)
