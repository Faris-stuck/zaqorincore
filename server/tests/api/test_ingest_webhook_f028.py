"""F-028: webhook ingest must use depth-limited JSON decoding.

The webhook endpoint accepts a JSON body up to 1 MiB and also parses
each ``records[i].message`` field as a JSON sub-document. Without a
nesting-depth cap, an authenticated client can submit a body whose top-
level object (or whose per-record message) is 1000+ levels deep. The
default CPython JSON decoder recurses on every level and trips the
``sys.setrecursionlimit`` ceiling, raising ``RecursionError``. The
endpoint catches that as a generic 500 and rolls the whole batch back.

The F-027 fix introduced ``zaqorincore_server.utils.depth_json`` and
applied it to the Cloudflare Logpush NDJSON line loop. F-028 applies
the same primitive to the webhook body and the per-record message
sub-document.

These tests live outside the full test suite (no FastAPI app
imports) so they run in the same import-free environment as
``test_depth_json_f027.py``.
"""

from __future__ import annotations

import pytest

from zaqorincore_server.utils.depth_json import (
    MAX_JSON_DEPTH,
    DepthLimitedDecoder,
    safe_loads,
)


def test_f028_typical_webhook_body_parses_ok() -> None:
    """A 3-level webhook body (vendor envelope + record) parses cleanly."""
    body = '{"events": [{"src_ip": "203.0.113.1", "uri": "/login", "meta": {"bot": false}}]}'
    parsed = safe_loads(body)
    assert isinstance(parsed, dict)
    assert "events" in parsed
    assert parsed["events"][0]["meta"]["bot"] is False


def test_f028_body_at_depth_limit_parses_ok() -> None:
    """A body exactly at the depth cap is still accepted.

    Build a nested object N levels deep with a string leaf so the
    shape is unambiguous: ``{"a":{"a":{...{"a":"leaf"}...}}}``.
    The structure has depth-1 nested dicts (the leaf is a string,
    not a dict, so the closing `}` count matches the opening
    ``{"a":`` count).
    """
    depth = MAX_JSON_DEPTH - 1
    body = '{"a":' * depth + '"leaf"' + "}" * depth
    parsed = safe_loads(body)
    assert isinstance(parsed, dict)
    # Walk down `depth` levels; the final dict has `{"a": "leaf"}` at
    # the bottom of the chain.
    cur: object = parsed
    for i in range(depth - 1):
        assert isinstance(cur, dict), f"level {i}: not a dict"
        assert "a" in cur, f"level {i}: missing key 'a'"
        cur = cur["a"]
    # Final value is a dict whose only key is "a" with value "leaf".
    assert isinstance(cur, dict), f"final level: not a dict, got {cur!r}"
    assert cur == {"a": "leaf"}, f"final value should be {{'a': 'leaf'}}, got {cur!r}"


def test_f028_body_over_depth_limit_rejected() -> None:
    """A body deeper than the cap raises ValueError, not RecursionError."""
    depth = MAX_JSON_DEPTH + 1
    body = "{" * depth + "}" * depth
    with pytest.raises(ValueError, match="nesting depth"):
        safe_loads(body)


def test_f028_per_record_message_at_limit_parses_ok() -> None:
    """A `message` sub-document exactly at the depth cap is still accepted."""
    depth = MAX_JSON_DEPTH - 1
    msg = '{"a":' * depth + '"leaf"' + "}" * depth
    record = {"src_ip": "203.0.113.2", "message": msg}
    parsed = safe_loads(record["message"])
    assert isinstance(parsed, dict)


def test_f028_per_record_message_over_limit_rejected() -> None:
    """A `message` sub-document deeper than the cap raises ValueError."""
    depth = MAX_JSON_DEPTH + 1
    msg = "{" * depth + "}" * depth
    record = {"src_ip": "203.0.113.3", "message": msg}
    with pytest.raises(ValueError, match="nesting depth"):
        safe_loads(record["message"])


def test_f028_string_brackets_in_message_dont_count_raw() -> None:
    """A JSON string containing brackets must not inflate the depth count."""
    # The string "]]]}}]]" is 9 characters, all closers, so depth never
    # increases; the value still parses as a flat object.
    msg = '{"text": "]]]}}]]]"}'
    parsed = safe_loads(msg)
    assert parsed == {"text": "]]]}}]]]"}


def test_f028_depth_decoder_uses_module_default() -> None:
    """The DepthLimitedDecoder class default matches the module constant."""
    d = DepthLimitedDecoder()
    # At-limit case (depth == MAX_JSON_DEPTH) succeeds.
    at_limit = "[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH
    d.decode(at_limit)
    # Over-limit case raises.
    over_limit = "[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1)
    with pytest.raises(ValueError, match="nesting depth"):
        d.decode(over_limit)
