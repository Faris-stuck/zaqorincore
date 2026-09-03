"""F-026: ensure Sigma rule loader error messages don't leak
rule-file source via PyYAML's default error formatter.

Before the fix, ``parse_rule_file`` interpolated ``str(e)`` (the
PyYAML error) into the SigmaRuleLoadError reason, which the
loader then logged. PyYAML's ``str(e)`` includes a snippet of
the offending source line.

After the fix, only the structured position info (line, column)
and the OSError class name are surfaced. The full source fragment
is still in the exception chain for in-process introspection,
but it never reaches a log or an HTTP response.
"""

from __future__ import annotations

import os
import secrets
import textwrap
from pathlib import Path

os.environ.setdefault("ZAQORIN_EVIDENCE_KEY", secrets.token_urlsafe(32))
os.environ.setdefault("ZAQORIN_CLOUDFLARE_INGEST_SECRET", secrets.token_urlsafe(32))
os.environ.setdefault("ZAQORIN_WEBHOOK_INGEST_SECRET", secrets.token_urlsafe(32))
os.environ.setdefault(
    "ZAQORIN_DATABASE_URL",
    "postgresql+asyncpg://zaqorin:secret@127.0.0.1:25432/zaqorin_test",
)
os.environ.setdefault("ZAQORIN_REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ.setdefault("ZAQORIN_STREAMS_ENABLED", "false")
os.environ.setdefault("ZAQORIN_DETECTORS_ENABLED", "false")

import pytest  # noqa: E402

from zaqorincore_server.rule_engine.sigma import (  # noqa: E402
    SigmaRuleLoadError,
    parse_rule_file,
)

# A distinctive secret marker. If this ever appears in the error
# message, the F-026 fix has regressed.
SECRET_MARKER = "zaqorin-f026-secret-7a3b9e1c4d8f2a6b"


def _write_bad_rule(tmp_path: Path) -> Path:
    """Write a YAML file that fails to parse.

    The SECRET_MARKER is included in the offending line so we can
    assert it does NOT appear in the loader's error message.
    """
    p = tmp_path / "bad.yml"
    p.write_text(
        textwrap.dedent(
            f"""\
            title: T-9999 (F-026)
            id: 11111111-1111-1111-1111-111111111111
            level: high
            detection:
              selection:
                event_type: {SECRET_MARKER}
                invalid_yaml: [unclosed
            """
        ),
        encoding="utf-8",
    )
    return p


def test_f026_yaml_error_omits_source(tmp_path: Path) -> None:
    """The SigmaRuleLoadError must NOT contain SECRET_MARKER.

    Pre-fix, the marker was in the PyYAML error's str (as a
    snippet of the offending line). Post-fix, only line + column
    are surfaced.
    """
    p = _write_bad_rule(tmp_path)
    with pytest.raises(SigmaRuleLoadError) as exc_info:
        parse_rule_file(p)
    msg = str(exc_info.value)
    assert SECRET_MARKER not in msg, (
        f"F-026 regression: SECRET_MARKER leaked into {msg!r}"
    )


def test_f026_yaml_error_includes_position(tmp_path: Path) -> None:
    """The error should mention line/column instead of source."""
    p = _write_bad_rule(tmp_path)
    with pytest.raises(SigmaRuleLoadError) as exc_info:
        parse_rule_file(p)
    msg = str(exc_info.value)
    # Post-fix message format: "invalid YAML at line N, column M"
    assert "invalid YAML at" in msg
    assert "line " in msg
    assert "column " in msg


def test_f026_yaml_error_excludes_snippet_markers(tmp_path: Path) -> None:
    """The PyYAML default format uses '\"<key>\": value' style snippets.

    Pre-fix, those fragments leaked. Post-fix, only the bare
    ``line N, column M`` form appears.
    """
    p = _write_bad_rule(tmp_path)
    with pytest.raises(SigmaRuleLoadError) as exc_info:
        parse_rule_file(p)
    msg = str(exc_info.value)
    # No quoted YAML key/value fragments should leak.
    assert "event_type" not in msg, (
        f"F-026 regression: YAML key leaked into {msg!r}"
    )
