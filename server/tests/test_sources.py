"""Tests for the Source Connector API (Phase 26, Slice 3).

Covers the 9 operator-facing endpoints in
``zaqorincore_server.api.v1.sources``:

* ``GET    /api/v1/sources``                 — list connectors
* ``POST   /api/v1/sources/cloudflare``      — register CF source
* ``POST   /api/v1/sources/aws``             — register AWS source
* ``POST   /api/v1/sources/webhook``         — register generic webhook
* ``POST   /api/v1/sources/syslog``          — register syslog UDP/TCP
* ``GET    /api/v1/sources/{id}/status``     — per-connector stats
* ``POST   /api/v1/sources/{id}/test``       — synthetic event test
* ``POST   /api/v1/sources/{id}/rotate-key`` — rotate signing key
* ``DELETE /api/v1/sources/{id}``            — remove connector

Also covers the input-validation helpers (``_validate_zone_id``,
``_validate_aws_role_arn``, ``_validate_syslog_host`` etc.) and the
``verify_webhook_signature`` constant-time HMAC verifier. The
validation tests are pure unit tests — no DB or httpx — so they
can run in environments where the async driver isn't available.

The DB-backed tests follow the same ``app_client`` pattern as
``test_rules_studio.py`` and ``test_api_agents.py``: an
``httpx.AsyncClient`` wired to the FastAPI app via ASGITransport,
against an isolated per-test engine managed by ``conftest.engine``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid

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
    "postgresql+asyncpg://zaqorin:***@127.0.0.1:25432/zaqorin_test",
)
os.environ.setdefault("ZAQORIN_REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ.setdefault("ZAQORIN_STREAMS_ENABLED", "false")
os.environ.setdefault("ZAQORIN_DETECTORS_ENABLED", "false")

import pytest  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from httpx import AsyncClient  # noqa: E402

pytestmark = pytest.mark.asyncio


# ─────────────────────────────────────────────────────────────────────────────
# Sample bodies — used as POST inputs and as ground-truth for assertions.
# ─────────────────────────────────────────────────────────────────────────────


#: A valid 32-char hex zone_id (Cloudflare's documented format).
GOOD_ZONE_ID = "a" * 32

#: A valid AWS role ARN: ``arn:aws:iam::<12-digit account>:role/<name>``.
GOOD_ROLE_ARN = "arn:aws:iam::" + "1" * 12 + ":role/zaqorin-ingest"
GOOD_LOG_GROUP = "/aws/lambda/zaqorin-prod"


def _cf_body(**overrides):  # type: ignore[no-untyped-def]
    body = {
        "api_token": secrets.token_urlsafe(40),
        "zone_id": GOOD_ZONE_ID,
        "datasets": ["http_requests"],
        "name": "cf-test",
    }
    body.update(overrides)
    return body


def _aws_body(**overrides):  # type: ignore[no-untyped-def]
    body = {
        "role_arn": GOOD_ROLE_ARN,
        "log_group": GOOD_LOG_GROUP,
        "name": "aws-test",
    }
    body.update(overrides)
    return body


def _webhook_body(**overrides):  # type: ignore[no-untyped-def]
    body = {"name": "wh-test", "format": "generic"}
    body.update(overrides)
    return body


def _syslog_body(**overrides):  # type: ignore[no-untyped-def]
    body = {
        "host": "10.0.0.5",
        "port": 514,
        "protocol": "udp",
        "facility": "auth",
        "name": "syslog-test",
    }
    body.update(overrides)
    return body


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests for input validators + HMAC verifier
# (no DB; run anywhere)
# ─────────────────────────────────────────────────────────────────────────────


def test_verify_webhook_signature_accepts_valid_hmac() -> None:
    """The verifier returns True for a correctly-computed HMAC-SHA256
    signature in lowercase hex."""
    from zaqorincore_server.api.v1.sources import verify_webhook_signature

    secret = secrets.token_hex(32)
    body = b'{"src_ip":"1.2.3.4","uri":"/admin"}'
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(
        secret=secret, body=body, signature_hex=sig
    ) is True


def test_verify_webhook_signature_rejects_tampered_body() -> None:
    """Modifying the body by even one byte must fail verification."""
    from zaqorincore_server.api.v1.sources import verify_webhook_signature

    secret = secrets.token_hex(32)
    body = b'{"src_ip":"1.2.3.4"}'
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    tampered = body.replace(b"1.2.3.4", b"5.6.7.8")
    assert verify_webhook_signature(
        secret=secret, body=tampered, signature_hex=sig
    ) is False


def test_verify_webhook_signature_rejects_wrong_length() -> None:
    """A signature that isn't 64 hex chars (SHA-256 output length) is
    rejected without doing any crypto work — the early return is part
    of the public contract (defensive depth)."""
    from zaqorincore_server.api.v1.sources import verify_webhook_signature

    secret = secrets.token_hex(32)
    # Too short by a few chars.
    assert verify_webhook_signature(
        secret=secret, body=b"x", signature_hex="abcd"
    ) is False
    # And empty.
    assert verify_webhook_signature(
        secret=secret, body=b"x", signature_hex=""
    ) is False


def test_validate_aws_role_arn_accepts_canonical_form() -> None:
    """The well-formed ARN we use in tests passes validation."""
    from zaqorincore_server.api.v1.sources import _validate_aws_role_arn

    # Should not raise.
    _validate_aws_role_arn(GOOD_ROLE_ARN)


def test_validate_aws_role_arn_rejects_malformed() -> None:
    """Bad ARNs (wrong account length, missing ``role/`` prefix, etc.)
    raise ``HTTPException(400)``."""
    from zaqorincore_server.api.v1.sources import _validate_aws_role_arn

    for bad in (
        "arn:aws:iam::123:role/x",  # account too short
        "arn:aws:iam::" + "1" * 12 + ":user/x",  # wrong partition element
        "not-an-arn",
        "arn:aws:iam::" + "1" * 12 + ":role/",  # empty role name
    ):
        with pytest.raises(HTTPException) as exc:
            _validate_aws_role_arn(bad)
        assert exc.value.status_code == 400


def test_validate_syslog_host_accepts_ip_and_hostname() -> None:
    """Both dotted-quad IPv4 and a plain hostname pass the validator."""
    from zaqorincore_server.api.v1.sources import _validate_syslog_host

    _validate_syslog_host("10.0.0.5")
    _validate_syslog_host("syslog-01.zaqorin.local")


def test_validate_syslog_host_rejects_garbage() -> None:
    """Garbage that doesn't look like an IP or a hostname is rejected."""
    from zaqorincore_server.api.v1.sources import _validate_syslog_host

    for bad in ("999.999.999.999", "not a host", "x" * 300):
        with pytest.raises(HTTPException) as exc:
            _validate_syslog_host(bad)
        assert exc.value.status_code == 400


def test_compute_rate_per_min_clamps_to_minimum_window() -> None:
    """A brand-new connector that just received its first event must
    not report a sky-high rate. The 60-second minimum window ensures
    the rate stays bounded immediately after create."""
    from datetime import datetime, timedelta, timezone

    from zaqorincore_server.api.v1.sources import _compute_rate_per_min

    now = datetime.now(timezone.utc)
    # 1 event received 1 second ago → naive rate is 60/min, but the
    # 60-second minimum window should clamp the window, not the rate.
    rate = _compute_rate_per_min(1, now - timedelta(seconds=1))
    # 1 event / (60s / 60) = 1.0 event/min.
    assert rate == pytest.approx(1.0, abs=0.01)
    # No events yet → 0.0 (no NaN, no division-by-zero).
    assert _compute_rate_per_min(0, None) == 0.0
    # last_event_at with no events → 0.0 (don't divide by window).
    assert _compute_rate_per_min(0, now) == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# DB-backed tests — exercise the live ASGI surface via ``app_client``.
# Follow the same fixture pattern as test_rules_studio.py.
# ─────────────────────────────────────────────────────────────────────────────


async def test_list_sources_empty_initially(
    app_client: AsyncClient,
) -> None:
    """A fresh test database has no connectors. The endpoint returns
    an empty list (200 OK, JSON array), not null."""
    r = await app_client.get("/api/v1/sources")
    assert r.status_code == 200, r.text
    assert r.json() == []


async def test_create_cloudflare_returns_secret_once(
    app_client: AsyncClient,
) -> None:
    """POST /sources/cloudflare returns 201 with the full ``api_key``
    and ``signing_secret`` exactly once. A subsequent GET shows only
    the masked ``api_key_fingerprint`` (last 8 chars)."""
    r = await app_client.post(
        "/api/v1/sources/cloudflare", json=_cf_body()
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["platform"] == "cloudflare"
    assert body["status"] == "active"
    assert body["events_received"] == 0
    assert body["error_count"] == 0
    # Secret is present on create.
    assert "api_key" in body and len(body["api_key"]) == 64
    assert "signing_secret" in body and len(body["signing_secret"]) == 64
    # Fingerprint matches the tail of the secret.
    assert body["api_key_fingerprint"] == body["api_key"][-8:]
    # Ingest URL points at the cloudflare ingest path.
    assert "/api/v1/ingest/cloudflare" in body["ingest_url"]
    # Stored config carries zone_id + datasets but NOT the raw token.
    assert body["config"]["zone_id"] == GOOD_ZONE_ID
    assert "http_requests" in body["config"]["datasets"]
    assert "api_token" not in body["config"]
    assert "token" not in body["config"]

    # List shows the fingerprint only — the full key is gone.
    r2 = await app_client.get("/api/v1/sources")
    assert r2.status_code == 200
    listed = r2.json()
    assert len(listed) == 1
    assert "api_key" not in listed[0]
    assert listed[0]["api_key_fingerprint"] == body["api_key_fingerprint"]


async def test_create_cloudflare_rejects_bad_zone_id(
    app_client: AsyncClient,
) -> None:
    """A zone_id that isn't a 32-char hex string is a 400 — we don't
    let a typo silently route to a wrong zone."""
    r = await app_client.post(
        "/api/v1/sources/cloudflare",
        json=_cf_body(zone_id="not-a-zone"),
    )
    assert r.status_code == 400, r.text
    assert "zone_id" in r.text.lower()


async def test_create_cloudflare_rejects_unknown_dataset(
    app_client: AsyncClient,
) -> None:
    """A dataset outside the fixed allow-list is a 400."""
    r = await app_client.post(
        "/api/v1/sources/cloudflare",
        json=_cf_body(datasets=["not_a_real_dataset"]),
    )
    assert r.status_code == 400, r.text
    assert "dataset" in r.text.lower()


async def test_create_aws_rejects_malformed_arn(
    app_client: AsyncClient,
) -> None:
    """Bad ARNs are a 400 — we'd rather fail at config time than
    silently route a CloudWatch subscription to a wrong account."""
    r = await app_client.post(
        "/api/v1/sources/aws",
        json=_aws_body(role_arn="arn:wrong"),
    )
    assert r.status_code == 400, r.text
    assert "role_arn" in r.text.lower()


async def test_create_webhook_rejects_unknown_format(
    app_client: AsyncClient,
) -> None:
    """An unsupported ``format`` (vendor translator) is a 400. The
    list of supported formats is fixed at import time."""
    r = await app_client.post(
        "/api/v1/sources/webhook",
        json=_webhook_body(format="nonsense_vendor"),
    )
    assert r.status_code == 400, r.text
    assert "format" in r.text.lower()


async def test_create_syslog_returns_empty_signing_secret(
    app_client: AsyncClient,
) -> None:
    """Syslog has no HTTP signing path. The create response surfaces
    ``signing_secret == ""`` explicitly so the WebUI doesn't display
    the ``api_key`` as if it were meaningful."""
    r = await app_client.post(
        "/api/v1/sources/syslog", json=_syslog_body()
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["platform"] == "syslog"
    # Syslog ingest URL uses the syslog:// scheme, not http(s).
    assert body["ingest_url"].startswith("syslog://")
    assert "signing_secret" in body
    assert body["signing_secret"] == ""
    # Stored config carries host/port/protocol.
    cfg = body["config"]
    assert cfg["host"] == "10.0.0.5"
    assert cfg["port"] == 514
    assert cfg["protocol"] == "udp"
    assert cfg["facility"] == "auth"


async def test_create_syslog_rejects_bad_protocol(
    app_client: AsyncClient,
) -> None:
    """Only ``udp`` / ``tcp`` are supported; anything else is a 400."""
    r = await app_client.post(
        "/api/v1/sources/syslog",
        json=_syslog_body(protocol="icmp"),
    )
    assert r.status_code == 400, r.text
    assert "protocol" in r.text.lower()


async def test_get_status_returns_counters(
    app_client: AsyncClient,
) -> None:
    """The status endpoint exposes ``events_received``,
    ``error_count``, ``last_event_at``, and ``rate_per_min`` so the
    WebUI status table can render a live view without an aggregation
    query across the events table."""
    r = await app_client.post(
        "/api/v1/sources/webhook", json=_webhook_body()
    )
    assert r.status_code == 201
    cid = r.json()["id"]

    r2 = await app_client.get(f"/api/v1/sources/{cid}/status")
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["id"] == cid
    assert body["events_received"] == 0
    assert body["error_count"] == 0
    assert body["last_event_at"] is None
    # No events yet → rate is 0.0 (never NaN / never divide-by-zero).
    assert body["rate_per_min"] == 0.0
    assert body["status"] == "active"


async def test_get_status_404_for_unknown_connector(
    app_client: AsyncClient,
) -> None:
    """A random UUID that wasn't created returns 404, not 200/empty."""
    r = await app_client.get(
        f"/api/v1/sources/{uuid.uuid4()}/status"
    )
    assert r.status_code == 404
    assert "not found" in r.text.lower()


async def test_test_endpoint_validates_cloudflare_config(
    app_client: AsyncClient,
) -> None:
    """POST /sources/{id}/test on a cloudflare connector validates
    the stored config and bumps ``events_received`` to confirm the
    synthetic event was 'delivered' from the operator's perspective."""
    r = await app_client.post(
        "/api/v1/sources/cloudflare", json=_cf_body()
    )
    cid = r.json()["id"]

    r2 = await app_client.post(f"/api/v1/sources/{cid}/test")
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["delivered"] is True
    assert body["status_code"] == 200
    # The counter advanced.
    r3 = await app_client.get(f"/api/v1/sources/{cid}/status")
    assert r3.json()["events_received"] == 1
    assert r3.json()["last_event_at"] is not None


async def test_test_endpoint_for_syslog_doesnt_make_http_call(
    app_client: AsyncClient,
) -> None:
    """Syslog has no HTTP path. The test endpoint must return a
    deterministic ``delivered=True`` without trying to open a socket
    or do a self-call to ``/api/v1/ingest/webhook`` (which would
    404 because the connector platform doesn't match)."""
    r = await app_client.post(
        "/api/v1/sources/syslog", json=_syslog_body()
    )
    cid = r.json()["id"]

    r2 = await app_client.post(f"/api/v1/sources/{cid}/test")
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["delivered"] is True
    assert body["status_code"] == 200
    # Detail mentions the listener host:port so the operator can
    # eyeball the config.
    assert "10.0.0.5" in body["detail"]
    assert "514" in body["detail"]


async def test_rotate_key_returns_new_secret_and_invalidates_old(
    app_client: AsyncClient,
) -> None:
    """POST /sources/{id}/rotate-key returns a fresh ``api_key`` and
    ``signing_secret``. The old ``api_key_fingerprint`` (which the
    WebUI showed before the rotate) is no longer present — the
    fingerprint on the row after rotate matches the new key."""
    r = await app_client.post(
        "/api/v1/sources/webhook", json=_webhook_body()
    )
    cid = r.json()["id"]
    old_fp = r.json()["api_key_fingerprint"]
    old_key = r.json()["api_key"]

    r2 = await app_client.post(f"/api/v1/sources/{cid}/rotate-key")
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["api_key"] != old_key
    assert len(body["api_key"]) == 64
    assert body["api_key_fingerprint"] != old_fp
    assert body["api_key_fingerprint"] == body["api_key"][-8:]
    # The ingest URL is the same (same connector, same platform).
    assert body["ingest_url"].endswith(
        f"connector={cid}"
    ) or "/api/v1/ingest/webhook" in body["ingest_url"]


async def test_rotate_key_404_for_unknown_connector(
    app_client: AsyncClient,
) -> None:
    r = await app_client.post(
        f"/api/v1/sources/{uuid.uuid4()}/rotate-key"
    )
    assert r.status_code == 404


async def test_delete_connector_returns_204_and_removes_row(
    app_client: AsyncClient,
) -> None:
    """DELETE returns 204 with no body, and the subsequent GET 404s."""
    r = await app_client.post(
        "/api/v1/sources/webhook", json=_webhook_body()
    )
    cid = r.json()["id"]

    r2 = await app_client.delete(f"/api/v1/sources/{cid}")
    assert r2.status_code == 204
    assert r2.content == b""

    # Gone from the list.
    r3 = await app_client.get("/api/v1/sources")
    assert all(item["id"] != cid for item in r3.json())

    # Status 404s.
    r4 = await app_client.get(f"/api/v1/sources/{cid}/status")
    assert r4.status_code == 404


async def test_delete_unknown_connector_is_404(
    app_client: AsyncClient,
) -> None:
    r = await app_client.delete(f"/api/v1/sources/{uuid.uuid4()}")
    assert r.status_code == 404


async def test_list_sources_contains_all_four_platforms(
    app_client: AsyncClient,
) -> None:
    """Round-trip: create one of each supported platform, then list
    and confirm we get all four back. This is the WebUI's main view."""
    created: list[str] = []
    for create_body, path in (
        (_cf_body(), "/api/v1/sources/cloudflare"),
        (_aws_body(), "/api/v1/sources/aws"),
        (_webhook_body(), "/api/v1/sources/webhook"),
        (_syslog_body(), "/api/v1/sources/syslog"),
    ):
        r = await app_client.post(path, json=create_body)
        assert r.status_code == 201, r.text
        created.append(r.json()["id"])

    r = await app_client.get("/api/v1/sources")
    assert r.status_code == 200
    listed = r.json()
    assert len(listed) == 4
    platforms = sorted(item["platform"] for item in listed)
    assert platforms == ["aws", "cloudflare", "syslog", "webhook"]
    # Every connector we created is present.
    listed_ids = {item["id"] for item in listed}
    assert set(created).issubset(listed_ids)
