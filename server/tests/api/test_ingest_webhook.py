"""Tests for /api/v1/ingest/webhook (generic webhook ingest).

Security contract (re-stated from ingest_webhook.py):
  1. X-API-Key auth via require_api_key (operator-only access).
  2. NO HMAC. Vendors that need HMAC get a translator in a follow-up.
  3. Body cap 1 MiB; per-field metadata cap 4096 chars.
  4. Required field: src_ip (records without it count toward rejected).
  5. Source detection: X-Event-Source header > body.source > default.

The shared API key used in these tests is a clearly fake value
(``test-webhook-key-do-not-use``) so it can never accidentally match a
real production secret. The default ``app_client`` fixture runs in
dev mode (ZAQORIN_API_KEY unset) so the require_api_key dep is a
no-op; tests that need auth active use the ``app_client_with_auth``
fixture pattern from ``test_routers_api_auth.py``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from zaqorincore_server.api.v1 import ingest_webhook as wh_mod
from zaqorincore_server.config import reset_settings
from zaqorincore_server.models import Event

pytestmark = pytest.mark.asyncio

# ---- Constants & helpers ----------------------------------------------------

ENDPOINT = "/api/v1/ingest/webhook"
API_KEY_HEADER = "X-API-Key"
TEST_API_KEY = "test-webhook-key-do-not-use"  # noqa: S105 - deliberately fake


def _single_event(
    *,
    src_ip: str = "203.0.113.10",
    method: str = "POST",
    uri: str = "/api/auth",
    status: int = 401,
    user_agent: str = "curl/8.4.0",
    host: str = "example.com",
    country: str = "US",
    asn: int = 13335,
    waf_action: str | None = None,
    waf_rule_id: str | None = None,
    bot_score: int | None = None,
    cache_status: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a single webhook event payload (generic vendor)."""
    rec: dict[str, Any] = {
        "src_ip": src_ip,
        "host": host,
        "method": method,
        "uri": uri,
        "status": status,
        "user_agent": user_agent,
        "country": country,
        "asn": asn,
    }
    if waf_action is not None:
        rec["waf_action"] = waf_action
        rec["waf_rule_id"] = waf_rule_id
    if bot_score is not None:
        rec["bot_score"] = bot_score
    if cache_status is not None:
        rec["cache_status"] = cache_status
    if extra:
        rec.update(extra)
    return rec


# ---- Tests ------------------------------------------------------------------


# 1. No auth -> 401
async def test_NoAuth_returns_401(
    monkeypatch: pytest.MonkeyPatch,
    app_client: AsyncClient,
) -> None:
    """Missing X-API-Key when ZAQORIN_API_KEY is set -> 401."""
    monkeypatch.setenv("ZAQORIN_API_KEY", TEST_API_KEY)
    reset_settings()
    body = json.dumps(_single_event()).encode("utf-8")
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 401, r.text
    assert r.headers.get("www-authenticate") == "ApiKey"


# 2. Wrong auth -> 401
async def test_WrongAuth_returns_401(
    monkeypatch: pytest.MonkeyPatch,
    app_client: AsyncClient,
) -> None:
    """Wrong X-API-Key value -> 401."""
    monkeypatch.setenv("ZAQORIN_API_KEY", TEST_API_KEY)
    reset_settings()
    body = json.dumps(_single_event()).encode("utf-8")
    r = await app_client.post(
        ENDPOINT,
        content=body,
        headers={API_KEY_HEADER: "wrong-value"},
    )
    assert r.status_code == 401, r.text
    assert r.headers.get("www-authenticate") == "ApiKey"


# 3. Single event, generic vendor, dev mode (no X-API-Key required)
async def test_SingleEventGeneric_accepted_one_rejected_zero(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """A well-formed single record -> {accepted: 1, rejected: 0, source: 'webhook'}."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    body = json.dumps(_single_event()).encode("utf-8")
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["accepted"] == 1
    assert data["rejected"] == 0
    assert data["source"] == wh_mod.SourceWebhookDefault

    async with factory() as session:
        rows = (
            await session.execute(
                select(Event).where(Event.source == wh_mod.SourceWebhookDefault)
            )
        ).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.metadata_["src_ip"] == "203.0.113.10"
    assert row.metadata_["method"] == "POST"
    assert row.metadata_["status"] == "401"
    assert row.metadata_["user_agent"] == "curl/8.4.0"
    assert row.metadata_["vendor"] == "generic"


# 4. Batch of 3 valid records
async def test_BatchEvent_accepted_three_rejected_zero(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """3 valid records in {'events': [...]} -> {accepted: 3, rejected: 0}."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    recs = [
        _single_event(src_ip=f"203.0.113.{i}", status=200 + i)
        for i in range(1, 4)
    ]
    body = json.dumps({"events": recs}).encode("utf-8")
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["accepted"] == 3
    assert data["rejected"] == 0

    async with factory() as session:
        rows = (
            await session.execute(
                select(Event).where(Event.source == wh_mod.SourceWebhookDefault)
            )
        ).scalars().all()
    assert len(rows) == 3
    src_ips = {r.metadata_["src_ip"] for r in rows}
    assert src_ips == {"203.0.113.1", "203.0.113.2", "203.0.113.3"}


# 5. Source from header wins over body
async def test_SourceFromHeader_wins_over_body(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """X-Event-Source header takes precedence over body's ``source`` field.

    Note: setting X-Event-Source to a known vendor name ALSO selects
    that vendor's translator. To keep this test focused on source
    detection, we send a body shape the generic translator would
    accept and a header value that is NOT a known vendor (so
    _pick_translator falls back to generic). Source detection is
    independent of translator selection.
    """
    factory = async_sessionmaker(engine, expire_on_commit=False)
    rec = _single_event()
    rec["source"] = "ignored_body_source"
    body = json.dumps(rec).encode("utf-8")
    # Use a non-vendor source so translator falls back to generic.
    r = await app_client.post(
        ENDPOINT,
        content=body,
        headers={wh_mod.EVENT_SOURCE_HEADER: "custom_upstream"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["source"] == "custom_upstream"

    async with factory() as session:
        row = (
            await session.execute(
                select(Event).where(Event.source == "custom_upstream")
            )
        ).scalar_one()
    assert row.source == "custom_upstream"


# 6. Source from body when no header
async def test_SourceFromBody_used_when_no_header(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """Body's ``source`` field used when no X-Event-Source header."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    rec = _single_event()
    rec["source"] = "elastic_webhook"
    body = json.dumps(rec).encode("utf-8")
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 200, r.text
    assert r.json()["source"] == "elastic_webhook"

    async with factory() as session:
        row = (
            await session.execute(
                select(Event).where(Event.source == "elastic_webhook")
            )
        ).scalar_one()
    assert row.source == "elastic_webhook"


# 7. Source default when no header and no body source
async def test_SourceDefault_when_no_header_no_body_source(
    app_client: AsyncClient,
) -> None:
    """No source anywhere -> 'webhook' default."""
    rec = _single_event()
    body = json.dumps(rec).encode("utf-8")
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 200, r.text
    assert r.json()["source"] == wh_mod.SourceWebhookDefault


# 8. Splunk HEC translation
async def test_SplunkHECTranslation_recognises_event_and_sourcetype(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """Splunk HEC body has {event: {...}, sourcetype: '...'}.

    Vendor is selected via ?vendor= query param so the test exercises
    the translator explicitly (rather than relying on the header also
    being the vendor name).
    """
    factory = async_sessionmaker(engine, expire_on_commit=False)
    splunk_body = {
        "event": _single_event(src_ip="198.51.100.42"),
        "sourcetype": "nginx:access:json",
    }
    r = await app_client.post(
        ENDPOINT + "?vendor=splunk_hec",
        content=json.dumps(splunk_body).encode("utf-8"),
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["accepted"] == 1
    assert data["rejected"] == 0
    # sourcetype becomes source (vendor seed) when no header or body source.
    assert data["source"] == "nginx:access:json"

    async with factory() as session:
        row = (
            await session.execute(
                select(Event).where(Event.source == "nginx:access:json")
            )
        ).scalar_one()
    assert row.metadata_["src_ip"] == "198.51.100.42"
    assert row.metadata_["vendor"] == "splunk_hec"


# 9. Elastic Watcher translation
async def test_ElasticWebhookTranslation_walks_hits_hits(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """Elastic body has hits.hits[*]._source with one or more entries."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    elastic_body = {
        "hits": {
            "hits": [
                {"_source": _single_event(src_ip="198.51.100.1", status=200)},
                {"_source": _single_event(src_ip="198.51.100.2", status=404)},
                {"_source": _single_event(src_ip="198.51.100.3", status=500)},
            ]
        }
    }
    body = json.dumps(elastic_body).encode("utf-8")
    r = await app_client.post(
        ENDPOINT, content=body, headers={wh_mod.EVENT_SOURCE_HEADER: "elastic_webhook"}
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["accepted"] == 3
    assert data["rejected"] == 0
    assert data["source"] == "elastic_webhook"

    async with factory() as session:
        rows = (
            await session.execute(select(Event))
        ).scalars().all()
    assert len(rows) == 3
    src_ips = sorted(r.metadata_["src_ip"] for r in rows)
    assert src_ips == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    for row in rows:
        assert row.metadata_["vendor"] == "elastic_webhook"


# 10. Sumo Logic translation - key=value message
async def test_SumoLogicTranslation_parses_key_value_message(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """Sumo body has records[].message as key=value string."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    sumo_body = {
        "records": [
            {
                "message": (
                    "src_ip=198.51.100.55 method=GET uri=/index.html "
                    "status=200 user_agent=sumo-agent/1.0"
                )
            }
        ]
    }
    body = json.dumps(sumo_body).encode("utf-8")
    r = await app_client.post(
        ENDPOINT, content=body, headers={wh_mod.EVENT_SOURCE_HEADER: "sumo_logic"}
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["accepted"] == 1
    assert data["rejected"] == 0
    assert data["source"] == "sumo_logic"

    async with factory() as session:
        row = (
            await session.execute(select(Event))
        ).scalar_one()
    assert row.metadata_["src_ip"] == "198.51.100.55"
    assert row.metadata_["method"] == "GET"
    assert row.metadata_["uri"] == "/index.html"
    assert row.metadata_["status"] == "200"
    assert row.metadata_["vendor"] == "sumo_logic"


# 11. Malformed/non-dict entry in batch
async def test_NonDictEntry_in_batch_dropped(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """Non-dict entries in a batch are silently dropped.

    The translator returns a list of dicts; anything that isn't a
    dict never enters the persist loop. We pair this with a record
    missing ``src_ip`` to exercise both the dropped and the rejected
    counter paths in one request.
    """
    factory = async_sessionmaker(engine, expire_on_commit=False)
    recs = [
        _single_event(src_ip="203.0.113.50"),
        "string-not-a-dict",
        ["array", "not", "a", "dict"],
        _single_event(src_ip="203.0.113.51"),  # also missing-src_ip below
    ]
    recs[-1] = {k: v for k, v in recs[-1].items() if k != "src_ip"}
    body = json.dumps({"events": recs}).encode("utf-8")
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 200, r.text
    data = r.json()
    # 1 valid + 2 non-dict (dropped) + 1 missing-src_ip (rejected)
    # Non-dict items: filtered out by translator, not counted as rejected.
    # Missing-src_ip dict: counted as rejected.
    assert data["accepted"] == 1
    assert data["rejected"] == 1

    async with factory() as session:
        rows = (
            await session.execute(select(Event))
        ).scalars().all()
    assert len(rows) == 1
    assert rows[0].metadata_["src_ip"] == "203.0.113.50"


async def test_TopLevelMalformedJSON_returns_422(
    app_client: AsyncClient,
) -> None:
    """Top-level body is not valid JSON -> 422."""
    body = b"{not even close to json"
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 422, r.text


# 12. Missing src_ip -> rejected
async def test_MissingSrcIP_counts_rejected(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """Record without src_ip -> counted toward rejected, not persisted."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    bad = _single_event()
    del bad["src_ip"]
    body = json.dumps({"events": [_single_event(), bad]}).encode("utf-8")
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["accepted"] == 1
    assert data["rejected"] == 1

    async with factory() as session:
        rows = (
            await session.execute(select(Event))
        ).scalars().all()
    assert len(rows) == 1


# 13. Body too large -> 413
async def test_BodyTooLarge_returns_413(
    app_client: AsyncClient,
) -> None:
    """Content-Length > 1 MiB -> 413."""
    big_body = b"x" * (wh_mod.MAX_BODY_BYTES + 1)
    r = await app_client.post(
        ENDPOINT,
        content=big_body,
        headers={"Content-Length": str(len(big_body))},
    )
    assert r.status_code == 413, r.text


# 14. Metadata truncation
async def test_MetadataTruncation_clips_4KB_user_agent(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """An 8 KiB user_agent is truncated to MAX_METADATA_CHARS in the DB."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    long_ua = "U" * 8192  # 8 KiB
    rec = _single_event(user_agent=long_ua)
    r = await app_client.post(
        ENDPOINT, content=json.dumps(rec).encode("utf-8")
    )
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] == 1

    async with factory() as session:
        row = (
            await session.execute(select(Event))
        ).scalar_one()
    assert len(row.metadata_["user_agent"]) == wh_mod.MAX_METADATA_CHARS
    assert all(c == "U" for c in row.metadata_["user_agent"])


# 15. Vendor selection via ?vendor= query param
async def test_ViaVendorQueryParam_picks_translator(
    app_client: AsyncClient,
    engine: Any,
) -> None:
    """?vendor=elastic_webhook picks the elastic translator."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    elastic_body = {
        "hits": {
            "hits": [
                {"_source": _single_event(src_ip="198.51.100.77", status=204)},
            ]
        }
    }
    body = json.dumps(elastic_body).encode("utf-8")
    r = await app_client.post(
        ENDPOINT + "?vendor=elastic_webhook", content=body
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["accepted"] == 1
    # No X-Event-Source header and no body.source -> vendor seed
    # is empty, falls through to default "webhook".
    assert data["source"] == wh_mod.SourceWebhookDefault

    async with factory() as session:
        row = (
            await session.execute(select(Event))
        ).scalar_one()
    assert row.metadata_["vendor"] == "elastic_webhook"
    assert row.metadata_["src_ip"] == "198.51.100.77"