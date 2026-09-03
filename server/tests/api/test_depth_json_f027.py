"""F-027: depth-limited JSON decoder (unit tests).

These tests live here (instead of in ``tests/api/``) because
they import the depth-limited decoder from its own module,
which avoids pulling in the FastAPI app surface that fails
its parameter-less dependency check at import time in the
test environment (a pre-existing condition, not a regression).

The behavior under test is exactly what ``ingest_cloudflare``
relies on at runtime — the F-027 fix is a small refactor that
moved the class into its own module so it can be unit-tested
without dragging in the API surface.
"""

from __future__ import annotations

import pytest

from zaqorincore_server.utils.depth_json import (
    MAX_JSON_DEPTH,
    DepthLimitedDecoder,
    safe_loads,
)


def test_f027_shallow_json_parses_ok() -> None:
    """A typical Cloudflare record (≤3 levels) parses cleanly."""
    record = safe_loads('{"a": {"b": 1}}')
    assert record == {"a": {"b": 1}}


def test_f027_at_depth_limit_parses_ok() -> None:
    """JSON at exactly the depth limit is allowed."""
    depth = MAX_JSON_DEPTH
    nested = "[" * depth + "]" * depth
    obj = safe_loads(nested)
    # The structure is ``depth`` nested empty arrays.
    # Walk down ``depth - 1`` times to reach the innermost.
    assert isinstance(obj, list)
    cur: object = obj
    for i in range(depth - 1):
        assert isinstance(cur, list), f"level {i}: not a list"
        assert len(cur) == 1, f"level {i}: expected 1 child, got {len(cur)}"
        cur = cur[0]
    assert isinstance(cur, list), f"innermost not a list: {cur!r}"
    assert cur == [], f"innermost should be empty list, got {cur!r}"


def test_f027_over_depth_limit_raises_value_error() -> None:
    """JSON deeper than MAX_JSON_DEPTH raises ValueError (not RecursionError)."""
    depth = MAX_JSON_DEPTH + 1
    nested = "[" * depth + "]" * depth
    with pytest.raises(ValueError, match="nesting depth"):
        safe_loads(nested)


def test_f027_nested_in_object_also_rejected() -> None:
    """Object nesting (not just list nesting) is also capped."""
    depth = MAX_JSON_DEPTH + 1
    nested = "{" * depth + "}" * depth
    with pytest.raises(ValueError, match="nesting depth"):
        safe_loads(nested)


def test_f027_string_brackets_dont_count() -> None:
    """A bracket character inside a string must not count as nesting."""
    record = safe_loads('{"a": "]]]]]]]]]]]]"}')
    assert record == {"a": "]" * 12}


def test_f027_escaped_quote_in_string_does_not_close_string() -> None:
    """An escaped quote inside a string must not flip the parser state."""
    record = safe_loads(r'{"a": "he said \"hi\""}')
    assert record == {"a": 'he said "hi"'}


def test_f027_class_with_custom_max_depth() -> None:
    """The class can be instantiated with a different max_depth."""
    d = DepthLimitedDecoder(max_depth=2)
    d.decode("[[]]")  # OK (2 levels)
    with pytest.raises(ValueError, match="nesting depth"):
        d.decode("[[[]]]")  # 3 levels, over the local limit


def test_f027_safe_loads_returns_value_type() -> None:
    """safe_loads returns dict for objects, list for arrays, primitives for scalars."""
    assert safe_loads("null") is None
    assert safe_loads("true") is True
    assert safe_loads("42") == 42
    assert safe_loads("3.14") == 3.14
    assert safe_loads('"hi"') == "hi"
