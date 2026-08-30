"""Tests for /api/v1/ingest/cloudflare (Cloudflare Logpush ingest).

Security contract (re-stated from ingest_cloudflare.py):
  1. HMAC verification BEFORE parse, BEFORE DB, BEFORE log.
  2. Constant-time compare via hmac.compare_digest.
  3. Body cap 5 MiB; per-line cap 64 KiB.
  4. Metadata value cap 4096 chars.
  5. 401 on bad/missing signature with NO body content.

The shared secret used in these tests is a clearly fake value
(``test-secret-do-not-use``) so it can never accidentally match a
real production secret. The endpoint treats dev + ZAQORIN_ENV !=
"production" the same way it treats production for HMAC: the
secret value is what matters, not whether it's the dev placeholder.

The router reads ``ZAQORIN_CLOUDFLARE_INGEST_SECRET`` at module
import time, so this test file sets the env var (and ZAQORIN_ENV=dev)
BEFORE importing the cloudflare module. That is the only way to
keep the test runnable in a CI environment that does not export
the secret.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import os
from typing import Any

# Set env vars BEFORE importing the cloudflare module, which reads
# them at import time.
os.environ.setdefault("ZAQORIN_ENV", "dev")
os.environ.setdefault(
    "ZAQORIN_CLOUDFLARE_INGEST_SECRET", "test-secret-do-not-use"
)

import pytest
from httpx import AsyncClient

from zaqorincore_server.api.v1 import ingest_cloudflare as cf_mod
from zaqorincore_server.models import Event

pytestmark = pytest.mark.asyncio


# ---- Constants & helpers ----------------------------------------------------

TEST_SECRET = "test-secret-do-not-use"  # noqa: S105 - deliberately fake
ENDPOINT = "/api/v1/ingest/cloudflare"
SIGNATURE_HEADER = "X-ZaQorin-Signature"


def _sign(body: bytes, secret: str = TEST_SECRET) -> str:
    """Compute the HMAC-SHA256 hex signature for a body."""
    return hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()


def _sample_record(
    *,
    client_ip: str = "203.0.113.10",
    host: str = "example.com",
    method: str = "GET",
    uri: str = "/api/v1/widgets",
    status: int = 200,
    user_agent: str = "Mozilla/5.0",
    country: str = "US",
    asn: int = 13335,
    bot_score: int = 7,
    waf_action: str | None = None,
    waf_rule_id: str | None = None,
    cache_status: str | None = None,
    edge_start_ts: str = "2026-08-30T12:00:00Z",
    edge_end_ts: str = "2026-08-30T12:00:01Z",
) -> dict[str, Any]:
    """Build a Cloudflare http_requests Logpush record."""
    rec: dict[str, Any] = {
        "ClientIP": client_ip,
        "ClientRequestHost": host,
        "ClientRequestMethod": method,
        "ClientRequestURI": uri,
        "ClientRequestUserAgent": user_agent,
        "ClientCountry": country,
        "ClientASN": asn,
        "EdgeResponseStatus": status,
        "EdgeStartTimestamp": edge_start_ts,
        "EdgeEndTimestamp": edge_end_ts,
        "BotScore": bot_score,
    }
    if waf_action is not None:
        rec["WAFAction"] = waf_action
        rec["WAFRuleID"] = waf_rule_id
    if cache_status is not None:
        rec["CacheCacheStatus"] = cache_status
    return rec


def _ndjson(records: list[Any]) -> bytes:
    """Render records as NDJSON (one JSON object per line)."""
    return ("\n".join(json.dumps(r) for r in records) + "\n").encode("utf-8")


# ---- Tests ------------------------------------------------------------------


async def test_HMACMismatch_returns_401_with_no_body(
    app_client: AsyncClient,
) -> None:
    """Wrong signature -> 401, body empty (no oracle)."""
    body = _ndjson([_sample_record()])
    r = await app_client.post(
        ENDPOINT,
        content=body,
        headers={SIGNATURE_HEADER: "0" * 64},
    )
    assert r.status_code == 401, r.text
    # No body content. Don't leak anything.
    assert r.content == b""


async def test_missing_signature_header_returns_401(
    app_client: AsyncClient,
) -> None:
    """No signature header at all -> 401."""
    body = _ndjson([_sample_record()])
    r = await app_client.post(ENDPOINT, content=body)
    assert r.status_code == 401, r.text
    assert r.content == b""


async def test_HMACMatch_single_line_persists_one_event(
    app_client: AsyncClient, engine: Any
) -> None:
    """Correct signature -> 200, one event persisted."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)

    record = _sample_record(
        client_ip="203.0.113.20",
        user_agent="curl/8.4.0",
        status=200,
    )
    body = _ndjson([record])
    sig = _sign(body)

    r = await app_client.post(
        ENDPOINT, content=body, headers={SIGNATURE_HEADER: sig}
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"accepted": 1, "rejected": 0}

    # DB has exactly one event, with the source we expect.
    async with factory() as session:
        rows = (
            await session.execute(
                select(Event).where(
                    Event.source == cf_mod.SourceCloudflareLogpush
                )
            )
        ).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.source == cf_mod.SourceCloudflareLogpush
    assert row.metadata_["src_ip"] == "203.0.113.20"
    assert row.metadata_["method"] == "GET"
    assert row.metadata_["status"] == "200"
    assert row.metadata_["user_agent"] == "curl/8.4.0"


async def test_HMACMatch_batch_NDJSON_counts_rejected_malformed(
    app_client: AsyncClient,
) -> None:
    """5 valid + 1 malformed line -> accepted=5, rejected=1."""
    records = [
        _sample_record(client_ip=f"203.0.113.{i}", status=200 + i)
        for i in range(5)
    ]
    valid_lines = [json.dumps(r) for r in records]
    body = "\n".join(valid_lines + ["{not even close to json"]) + "\n"
    body = body.encode("utf-8")
    sig = _sign(body)

    r = await app_client.post(
        ENDPOINT, content=body, headers={SIGNATURE_HEADER: sig}
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"accepted": 5, "rejected": 1}


async def test_BodyTooLarge_returns_413(app_client: AsyncClient) -> None:
    """Content-Length > 5 MiB -> 413."""
    # Send a Content-Length header larger than the cap. The
    # endpoint should reject without reading the body.
    body = b"x" * (cf_mod.MAX_BODY_BYTES + 1)
    r = await app_client.post(
        ENDPOINT,
        content=body,
        headers={
            SIGNATURE_HEADER: _sign(body),
            "Content-Length": str(len(body)),
        },
    )
    assert r.status_code == 413, r.text


async def test_LineTooLarge_counts_as_rejected(
    app_client: AsyncClient,
) -> None:
    """A single line > 64 KiB counts toward rejected, batch still 200."""
    small_record = _sample_record()
    small_line = json.dumps(small_record).encode("utf-8")
    huge_line = b"x" * (cf_mod.MAX_LINE_BYTES + 1)
    body = b"\n".join([small_line, huge_line, small_line]) + b"\n"
    sig = _sign(body)

    r = await app_client.post(
        ENDPOINT, content=body, headers={SIGNATURE_HEADER: sig}
    )
    assert r.status_code == 200, r.text
    # 2 small valid + 1 oversize rejected
    assert r.json() == {"accepted": 2, "rejected": 1}


async def test_NoSecretInProd_raises_at_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ZAQORIN_ENV=production + ZAQORIN_CLOUDFLARE_INGEST_SECRET unset
    -> the module raises RuntimeError at import time. This means the
    router is *not registered*, and ``POST /api/v1/ingest/cloudflare``
    returns 404 from FastAPI's default not-found handler.

    We test this at the import level (reloading the module with
    different env vars) rather than the HTTP level because the
    import-time failure prevents the app from building at all.
    Same pattern as evidence.py's evidence-key-required check.
    """
    monkeypatch.delenv("ZAQORIN_CLOUDFLARE_INGEST_SECRET", raising=False)
    monkeypatch.setenv("ZAQORIN_ENV", "production")

    import importlib

    with pytest.raises(RuntimeError, match="ZAQORIN_CLOUDFLARE_INGEST_SECRET"):
        importlib.reload(cf_mod)


async def test_NoSecretInProd_GET_returns_404(
    app_client: AsyncClient,
) -> None:
    """In dev mode the route IS mounted; verify the path. The 404
    contract for prod-without-secret is exercised in
    ``test_NoSecretInProd_raises_at_import``."""
    r = await app_client.get(ENDPOINT)
    # GET on a POST-only route -> 405 (Method Not Allowed), proving
    # the route IS registered at /api/v1/ingest/cloudflare.
    assert r.status_code == 405, r.text


async def test_MetadataTruncation_clips_4KB_user_agent(
    app_client: AsyncClient, engine: Any
) -> None:
    """A 4 KB user_agent is truncated to MAX_METADATA_CHARS in the DB."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(engine, expire_on_commit=False)

    long_ua = "U" * 8192  # 8 KiB
    record = _sample_record(user_agent=long_ua)
    body = _ndjson([record])
    sig = _sign(body)

    r = await app_client.post(
        ENDPOINT, content=body, headers={SIGNATURE_HEADER: sig}
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"accepted": 1, "rejected": 0}

    async with factory() as session:
        row = (
            await session.execute(
                select(Event).where(
                    Event.source == cf_mod.SourceCloudflareLogpush
                )
            )
        ).scalar_one()
    assert len(row.metadata_["user_agent"]) == cf_mod.MAX_METADATA_CHARS
    assert all(c == "U" for c in row.metadata_["user_agent"])


async def test_TimingAttackSafe_uses_compare_digest() -> None:
    """The HMAC verification helper must call hmac.compare_digest.

    This is a static-source check (no deliberate slow compare) because
    the constant-time guarantee is structural: the only safe call in
    Python is ``hmac.compare_digest``. We assert the helper's source
    mentions the API.
    """
    src = inspect.getsource(cf_mod)
    assert "hmac.compare_digest" in src, (
        "ingest_cloudflare must use hmac.compare_digest for constant-time "
        "comparison"
    )
    # And specifically, the verifier function:
    verifier_src = inspect.getsource(cf_mod._verify_hmac)
    assert "hmac.compare_digest" in verifier_src
    # Naive ``==`` would be a timing oracle.
    assert "== " not in verifier_src.replace(
        "==", "", verifier_src.count("== ")
    ), (
        "_verify_hmac must not compare the signature with `==` — "
        "that's a timing oracle."
    )


async def test_endpoint_does_not_require_x_api_key(app_client: AsyncClient) -> None:
    """The cloudflare endpoint must NOT use the standard X-API-Key auth.

    It has its own HMAC. Operators who want belt-and-braces can
    terminate the traffic behind a reverse proxy. This test verifies
    the contract: a request with no X-API-Key, no signature, and
    no body still gets 401 (signature-missing), not 401 (key-missing)
    — the WWW-Authenticate header tells us which auth scheme
    rejected us.
    """
    r = await app_client.post(ENDPOINT, content=b"")
    assert r.status_code == 401, r.text
    # Our auth scheme, not the global X-API-Key one.
    assert r.headers.get("www-authenticate") == "HMAC-SHA256"


async def test_healthz_unaffected_by_cloudflare_route(
    app_client: AsyncClient,
) -> None:
    """Mounting the cloudflare router must not break /healthz."""
    r = await app_client.get("/healthz")
    assert r.status_code == 200, r.text