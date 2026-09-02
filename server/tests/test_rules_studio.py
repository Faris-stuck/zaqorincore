"""Tests for the Rule Studio API (Phase 26, Slice 2).

Covers:
* GET /api/v1/rules              — list builtin + custom
* GET /api/v1/rules/{rule_id}    — fetch YAML + parsed AST
* POST /api/v1/rules             — create, validates Sigma schema
* PUT /api/v1/rules/{rule_id}    — overwrite
* DELETE /api/v1/rules/{rule_id} — remove from custom (built-in immutable)
* POST /api/v1/rules/{rule_id}/test — bench against synthetic event
* POST /api/v1/rules/reload      — engine hot-reload signal

The fixture clears the ZAQORIN_* secrets the package imports require
so the test app boots in a hermetic fashion. Tests then read & write
to the real ``rules/builtin/`` and ``rules/custom/`` directories —
the latter is created on demand and cleaned up after each test so
the operator's existing custom rules (if any) are not affected.
"""

from __future__ import annotations

import os
import secrets

# Boot-time env the package import demands — generate ephemeral
# secrets so the test doesn't depend on the shell's environment.
os.environ.setdefault(
    "ZAQORIN_EVIDENCE_KEY", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_CLOUDFLARE_INGEST_SECRET", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_WEBHOOK_INGEST_SECRET", secrets.token_urlsafe(32)
)
os.environ.setdefault(
    "ZAQORIN_DATABASE_URL",
    "postgresql+asyncpg://zaqorin:secret@127.0.0.1:25432/zaqorin_test",
)
os.environ.setdefault("ZAQORIN_REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ.setdefault("ZAQORIN_STREAMS_ENABLED", "false")
os.environ.setdefault("ZAQORIN_DETECTORS_ENABLED", "false")

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from httpx import AsyncClient  # noqa: E402

pytestmark = pytest.mark.asyncio


# ─────────────────────────────────────────────────────────────────────────────
# Filesystem layout — must match rules_studio.py
# ─────────────────────────────────────────────────────────────────────────────


_SERVER_ROOT = Path(__file__).resolve().parents[1]
_BUILTIN_DIR = _SERVER_ROOT / "rules" / "builtin"
_CUSTOM_DIR = _SERVER_ROOT / "rules" / "custom"


def _rm_custom_rules() -> None:
    """Remove every rule we wrote under rules/custom/ for the
    test. Built-ins are never touched."""
    if not _CUSTOM_DIR.exists():
        return
    for path in _CUSTOM_DIR.iterdir():
        if path.suffix in (".yml", ".yaml") and not path.name.startswith("."):
            path.unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def _clean_custom_rules():
    """Snapshot and restore rules/custom/ around every test so a
    run doesn't pollute the operator's local working tree."""
    _rm_custom_rules()
    yield
    _rm_custom_rules()


# ─────────────────────────────────────────────────────────────────────────────
# Sample rules — used as POST bodies and as on-disk fixtures.
# ─────────────────────────────────────────────────────────────────────────────


VALID_RULE = {
    "title": "Test SSH brute force",
    "id": "test-ssh-bruteforce",
    "level": "high",
    "logsource": "sshd",
    "mitre_id": "T1110",
    "detection": {
        "selection": {"source": "sshd", "status": "failed"},
    },
    "condition": "selection",
    "timeframe": "60s",
    "count": 5,
    "cooldown_sec": 300,
    "dedup_key": "{{source_ip}}",
    "tags": ["attack.t1110", "test"],
}


def _build_with_invalid_condition() -> dict:
    return {
        **VALID_RULE,
        "id": "test-bad-condition",
        "title": "Bad condition test",
        "condition": "selection and not (A or B)",  # not supported
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


async def test_list_rules_returns_builtins(
    app_client: AsyncClient,
) -> None:
    """The built-in directory ships at least one rule; the listing
    surfaces it with ``source == 'builtin'``."""
    r = await app_client.get("/api/v1/rules")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list)
    assert any(item["id"] == "builtin-ssh-bruteforce" for item in body), (
        "expected built-in ssh rule in listing, got ids: "
        + ", ".join(item["id"] for item in body)
    )
    ssh = next(
        item for item in body if item["id"] == "builtin-ssh-bruteforce"
    )
    assert ssh["source"] == "builtin"
    assert ssh["level"] == "high"
    # Built-in has MITRE tag → mitre_id is populated.
    assert ssh["mitre_id"] is not None


async def test_get_rule_returns_yaml_and_ast(
    app_client: AsyncClient,
) -> None:
    """GET /api/v1/rules/{rule_id} returns the raw YAML and the
    parsed detection block for the editor."""
    r = await app_client.get("/api/v1/rules/builtin-ssh-bruteforce")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "builtin-ssh-bruteforce"
    assert body["source"] == "builtin"
    assert "yaml" in body and body["yaml"].strip().startswith("title:")
    assert "detection" in body
    assert "selection" in body["detection"]
    assert body["condition"] == "selection"
    assert body["cooldown_sec"] == 300
    assert body["action"] is not None
    assert body["action"]["kind"] == "block_ip"


async def test_get_rule_404_when_missing(
    app_client: AsyncClient,
) -> None:
    r = await app_client.get("/api/v1/rules/does-not-exist-zzzz")
    assert r.status_code == 404
    assert "not found" in r.text.lower()


async def test_create_rule_round_trip(
    app_client: AsyncClient,
) -> None:
    """POST writes the rule, GET returns it. The on-disk YAML
    matches what the runtime Sigma loader accepts."""
    r = await app_client.post("/api/v1/rules", json=VALID_RULE)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["id"] == "test-ssh-bruteforce"
    assert body["title"] == "Test SSH brute force"
    assert body["source"] == "custom"
    assert body["level"] == "high"

    # File landed in the right place.
    on_disk = _CUSTOM_DIR / "test-ssh-bruteforce.yml"
    assert on_disk.exists()

    # GET round-trip.
    r2 = await app_client.get("/api/v1/rules/test-ssh-bruteforce")
    assert r2.status_code == 200
    assert r2.json()["id"] == "test-ssh-bruteforce"


async def test_create_rule_rejects_duplicate(
    app_client: AsyncClient,
) -> None:
    """A second POST for the same id is a 409, not a silent overwrite."""
    r1 = await app_client.post("/api/v1/rules", json=VALID_RULE)
    assert r1.status_code == 201
    r2 = await app_client.post("/api/v1/rules", json=VALID_RULE)
    assert r2.status_code == 409, r2.text
    assert "already exists" in r2.text.lower()


async def test_create_rule_rejects_invalid_condition(
    app_client: AsyncClient,
) -> None:
    """Conditions outside the supported pattern set are rejected
    at the edge (see PITFALLS in the slice plan — compound NOT
    forms are NOT supported by the runtime engine)."""
    r = await app_client.post(
        "/api/v1/rules", json=_build_with_invalid_condition()
    )
    assert r.status_code == 422, r.text
    assert "unsupported condition" in r.text.lower()


async def test_create_rule_rejects_missing_selection(
    app_client: AsyncClient,
) -> None:
    """A Sigma rule without ``detection.selection`` is invalid."""
    r = await app_client.post(
        "/api/v1/rules",
        json={
            "title": "broken",
            "id": "test-broken",
            "level": "low",
            "detection": {"condition": "selection"},
        },
    )
    assert r.status_code == 422


async def test_create_rule_rejects_bad_id(
    app_client: AsyncClient,
) -> None:
    """Rule ids must match [a-z0-9][a-z0-9-]{1,62}[a-z0-9]."""
    r = await app_client.post(
        "/api/v1/rules",
        json={
            **VALID_RULE,
            "id": "BAD ID with spaces and !@#",
        },
    )
    assert r.status_code == 422, r.text


async def test_create_rule_auto_id_when_omitted(
    app_client: AsyncClient,
) -> None:
    """Omitting ``id`` derives one from the title (kebab-case)."""
    payload = {**VALID_RULE, "id": None}
    payload.pop("id")
    r = await app_client.post("/api/v1/rules", json=payload)
    assert r.status_code == 201, r.text
    assert r.json()["id"] == "test-ssh-brute-force"


async def test_update_rule_overwrites(
    app_client: AsyncClient,
) -> None:
    """PUT replaces the file. Built-ins are rejected as 409."""
    # Create first.
    r0 = await app_client.post("/api/v1/rules", json=VALID_RULE)
    assert r0.status_code == 201

    updated = {**VALID_RULE, "level": "critical", "count": 10}
    r1 = await app_client.put(
        "/api/v1/rules/test-ssh-bruteforce", json=updated
    )
    assert r1.status_code == 200, r1.text
    body = r1.json()
    assert body["level"] == "critical"

    # Re-read via GET — change actually persisted.
    r2 = await app_client.get("/api/v1/rules/test-ssh-bruteforce")
    assert r2.json()["level"] == "critical"
    assert r2.json()["detection"]["count"] == 10


async def test_update_builtin_is_rejected(
    app_client: AsyncClient,
) -> None:
    """Built-ins are read-only — PUT against a builtin id returns 409."""
    r = await app_client.put(
        "/api/v1/rules/builtin-ssh-bruteforce",
        json={**VALID_RULE, "id": "builtin-ssh-bruteforce"},
    )
    assert r.status_code == 409, r.text
    assert "built-in" in r.text.lower()


async def test_update_missing_rule_is_404(
    app_client: AsyncClient,
) -> None:
    """PUT on a non-existent rule is a 404, not a create."""
    r = await app_client.put(
        "/api/v1/rules/never-existed", json=VALID_RULE
    )
    assert r.status_code == 404


async def test_delete_custom_rule(
    app_client: AsyncClient,
) -> None:
    """DELETE removes a custom rule and returns 204."""
    r0 = await app_client.post("/api/v1/rules", json=VALID_RULE)
    assert r0.status_code == 201

    r = await app_client.delete("/api/v1/rules/test-ssh-bruteforce")
    assert r.status_code == 204, r.text
    assert r.content == b""

    # File gone.
    assert not (_CUSTOM_DIR / "test-ssh-bruteforce.yml").exists()

    # GET now 404s.
    r2 = await app_client.get("/api/v1/rules/test-ssh-bruteforce")
    assert r2.status_code == 404


async def test_delete_builtin_is_rejected(
    app_client: AsyncClient,
) -> None:
    """Built-ins cannot be deleted — DELETE returns 409."""
    r = await app_client.delete("/api/v1/rules/builtin-ssh-bruteforce")
    assert r.status_code == 409
    assert "built-in" in r.text.lower()
    # And the file is still there.
    assert (_BUILTIN_DIR / "ssh_bruteforce.yml").exists()


async def test_delete_missing_rule_is_404(
    app_client: AsyncClient,
) -> None:
    r = await app_client.delete("/api/v1/rules/never-existed")
    assert r.status_code == 404


async def test_test_bench_matches_known_rule(
    app_client: AsyncClient,
) -> None:
    """Run the bench against the built-in ssh rule with a sample
    log that exercises the selection."""
    r = await app_client.post(
        "/api/v1/rules/builtin-ssh-bruteforce/test",
        json={
            "sample_log": "Failed password for root from 10.0.0.5",
            "log_format": "plain",
            "metadata": {
                "source": "sshd",
                "status": "failed",
                "source_ip": "10.0.0.5",
            },
            "source": "sshd",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["matched"] is True
    # Evidence surfaces the would-be action so the operator can
    # eyeball what would happen on a real fire.
    assert any("block_ip" in e for e in body["evidence"])


async def test_test_bench_no_match_on_unrelated_sample(
    app_client: AsyncClient,
) -> None:
    """A sample that doesn't match the rule returns matched=False
    with no evidence — the parse_errors list is empty (plain log,
    nothing to parse)."""
    r = await app_client.post(
        "/api/v1/rules/builtin-ssh-bruteforce/test",
        json={
            "sample_log": "irrelevant log line",
            "log_format": "plain",
            "metadata": {"source": "httpd", "status": "200"},
            "source": "httpd",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["matched"] is False
    assert body["evidence"] == []
    assert body["parse_errors"] == []


async def test_test_bench_handles_json_log_format(
    app_client: AsyncClient,
) -> None:
    """A JSON-formatted sample is parsed; top-level keys populate
    the event metadata so the rule's selection matches."""
    r = await app_client.post(
        "/api/v1/rules/builtin-ssh-bruteforce/test",
        json={
            "sample_log": (
                    '{"source": "sshd", "status": "failed", '
                    '"source_ip": "10.0.0.7", "msg": "auth fail"}'
                ),
            "log_format": "json",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["matched"] is True


async def test_test_bench_handles_syslog_log_format(
    app_client: AsyncClient,
) -> None:
    """A syslog-formatted sample populates ``hostname``/``process``
    in metadata. With the right metadata the rule matches."""
    r = await app_client.post(
        "/api/v1/rules/builtin-ssh-bruteforce/test",
        json={
            "sample_log": (
                "Mar 15 14:23:01 host01 sshd[12345]: "
                "Failed password for root from 10.0.0.9"
            ),
            "log_format": "syslog",
            "metadata": {"status": "failed"},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["matched"] is True


async def test_test_bench_against_custom_rule(
    app_client: AsyncClient,
) -> None:
    """Round-trip: POST a custom rule, run the bench against it."""
    r0 = await app_client.post("/api/v1/rules", json=VALID_RULE)
    assert r0.status_code == 201

    r = await app_client.post(
        "/api/v1/rules/test-ssh-bruteforce/test",
        json={
            "sample_log": "synthetic sample",
            "log_format": "plain",
            "metadata": {"source": "sshd", "status": "failed"},
            "source": "sshd",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["matched"] is True


async def test_reload_returns_counts(
    app_client: AsyncClient,
) -> None:
    """Reload returns builtin_count and custom_count, both >= 0."""
    # Create one custom rule so the custom count is at least 1.
    r0 = await app_client.post("/api/v1/rules", json=VALID_RULE)
    assert r0.status_code == 201

    r = await app_client.post("/api/v1/rules/reload")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reloaded"] is True
    assert body["builtin_count"] >= 1
    assert body["custom_count"] >= 1
    # Reload sentinel landed on disk.
    sentinel = _SERVER_ROOT / "rules" / ".reload-signal"
    assert sentinel.exists()


async def test_reload_collects_load_errors(
    app_client: AsyncClient,
) -> None:
    """A malformed custom YAML is reported in load_errors rather
    than crashing the endpoint."""
    bad_path = _CUSTOM_DIR / "bad-syntax.yml"
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_text("title: [unclosed bracket\n", encoding="utf-8")
    try:
        r = await app_client.post("/api/v1/rules/reload")
        assert r.status_code == 200, r.text
        body = r.json()
        assert any("bad-syntax" in e for e in body["load_errors"])
    finally:
        bad_path.unlink(missing_ok=True)