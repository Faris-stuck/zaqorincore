"""Pytest config for integration tests."""

from __future__ import annotations

import importlib
import os
import sys
import types

# Tests that mount routers directly intentionally exercise endpoint behavior
# without real credentials. This is test-only; production defaults fail closed.
os.environ.setdefault("ZAQORIN_ALLOW_UNAUTHENTICATED", "true")

_V1_LEAVES = (
    "agents", "agents_provision", "alerts", "audit", "audit_bots", "auth",
    "canary", "evidence", "events", "healthcheck", "hosts", "hunt",
    "ingest_cloudflare", "ingest_webhook", "rules_studio", "security",
    "sources", "stats", "stream", "version",
)


def _stub_module(name: str) -> types.ModuleType:
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m


for k in list(sys.modules):
    if k.startswith("zaqorincore_server.api"):
        del sys.modules[k]

import zaqorincore_server  # noqa: F401,E402

_api_pkg = _stub_module("zaqorincore_server.api")
_api_pkg.__path__ = ["src/zaqorincore_server/api"]  # type: ignore[attr-defined]
_stub_module("zaqorincore_server.api.health")

_v1_pkg = _stub_module("zaqorincore_server.api.v1")
_v1_pkg.__path__ = ["src/zaqorincore_server/api/v1"]  # type: ignore[attr-defined]

for _leaf in _V1_LEAVES:
    if _leaf != "agents_provision":
        _stub_module(f"zaqorincore_server.api.v1.{_leaf}")

importlib.import_module("zaqorincore_server.api.v1.agents_provision")
