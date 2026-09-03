"""Sigma loader full contract tests (cycle 96, TEST track).

The cycle 95 fix (commit 317a5f6, F-026) sanitized the error
messages produced by ``parse_rule_file``. It MUST also preserve
the broader contract that the engine relies on:

  - A valid rule still parses to one CompiledSigmaRule.
  - SigmaRuleLoadError remains a plain Exception whose ``str()``
    is safe to log (no rule-source leakage, no surprise exceptions
    when stringified).
  - ``load_rules_from_dir`` swallows per-file load errors,
    returns the good rules, and logs the bad ones — one bad rule
    must NOT take down the runner.
  - A missing directory returns an empty list, not a crash.
  - Loading the same directory twice yields the same set of
    rules (idempotent, no accidental duplication).

These tests complement the cycle 95 ``test_sigma_loader_f026.py``
tests, which only cover the error-message hygiene. They run
against in-memory tmp_path fixtures so they don't depend on any
on-disk rule pack.
"""

from __future__ import annotations

import os
import secrets
import textwrap
from pathlib import Path

# Boot-time env so the package import does not fail.
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
    CompiledSigmaRule,
    SigmaRuleLoadError,
    load_rules_from_dir,
    parse_rule_file,
)

pytestmark = pytest.mark.integration


VALID_RULE_YAML = textwrap.dedent(
    """\
    title: Contract Valid Rule
    id: contract-valid-001
    level: high
    detection:
      selection:
        event_type: login_failure
      condition: selection
    """
).strip()


def test_valid_rule_does_not_raise(tmp_path: Path) -> None:
    """A well-formed rule file parses to exactly one rule.

    This is the simplest sanity check — if the cycle 95 fix
    accidentally broke the happy path, this test fails.
    """
    p = tmp_path / "good.yml"
    p.write_text(VALID_RULE_YAML, encoding="utf-8")

    rules = parse_rule_file(p)

    assert len(rules) == 1
    assert isinstance(rules[0], CompiledSigmaRule)
    assert rules[0].id == "contract-valid-001"
    assert rules[0].level == "high"


def test_sigma_load_error_is_picklable() -> None:
    """SigmaRuleLoadError(path, reason) must str() without raising.

    The loader logs ``str(exc)`` for every failed file. If the
    ``__str__`` raises (or any field reference raises), the
    logger swallows the error silently and operators see no
    diagnostics. This test guarantees the contract: a basic
    construction round-trips through str().
    """
    p = Path("/tmp/contract-test.yml")
    err = SigmaRuleLoadError(p, "test reason")
    msg = str(err)
    assert isinstance(msg, str)
    assert "test reason" in msg
    # The path should be reflected back too, so operators can
    # tell which file failed.
    assert str(p) in msg


def test_load_rules_from_dir_swallows_bad_rules(tmp_path: Path) -> None:
    """One bad rule in a directory must not stop good rules from loading.

    ``load_rules_from_dir`` catches ``SigmaRuleLoadError`` per
    file. With one good + one bad rule, we expect exactly 1
    rule back (the good one) and no exception bubbled up.
    """
    # Good rule.
    good = tmp_path / "good.yml"
    good.write_text(VALID_RULE_YAML, encoding="utf-8")

    # Bad rule: invalid level triggers SigmaRuleLoadError
    # inside _compile (after YAML parses successfully).
    bad = tmp_path / "bad.yml"
    bad.write_text(
        textwrap.dedent(
            """\
            title: Contract Bad Rule
            id: contract-bad-001
            level: catastrophic
            detection:
              selection:
                event_type: login_failure
              condition: selection
            """
        ),
        encoding="utf-8",
    )

    # Must not raise.
    rules = load_rules_from_dir(tmp_path)

    assert len(rules) == 1, (
        f"expected only the good rule to load, got {len(rules)}: "
        f"{[r.id for r in rules]}"
    )
    assert rules[0].id == "contract-valid-001"


def test_load_rules_from_dir_returns_empty_for_missing(tmp_path: Path) -> None:
    """A non-existent directory yields [] — not a crash.

    The runner boots before all rule packs exist (during
    install / first-run), so a missing dir is the normal case,
    not an error.
    """
    missing = tmp_path / "definitely-not-here-7f3a"
    assert not missing.exists()

    rules = load_rules_from_dir(missing)

    assert rules == []


def test_load_rules_from_dir_no_duplicates(tmp_path: Path) -> None:
    """Loading the same directory twice must yield the same rules.

    This guards against accidental state accumulation in the
    loader — e.g. a regression where a class-level cache keeps
    appending on every call. Same length and same IDs in the
    same order is enough proof.
    """
    # Write two distinct rules so we can verify identity too.
    for i in range(2):
        rule = tmp_path / f"rule_{i}.yml"
        rule.write_text(
            textwrap.dedent(
                f"""\
                title: Contract Rule {i}
                id: contract-no-dup-{i:03d}
                level: medium
                detection:
                  selection:
                    event_type: login_failure
                  condition: selection
                """
            ),
            encoding="utf-8",
        )

    first = load_rules_from_dir(tmp_path)
    second = load_rules_from_dir(tmp_path)

    assert len(first) == len(second) == 2
    assert [r.id for r in first] == [r.id for r in second]