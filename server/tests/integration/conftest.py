"""Pytest config for tests/integration/.

The full ``zaqorincore_server.api.v1`` package import chain hits a
pre-existing "parameter-less dependency" collection error in
``api.v1.stats``. Per the cycle 57 brief, that error is
**unrelated** to this cycle and is ignored.

But our install-command test needs to import just the
``agents_provision`` router. We work around the broken import
chain by stubbing the broken submodule leaves at *module load*
time (before pytest collection) so the package ``__init__``
chain can complete.

IMPORTANT: this conftest must NOT itself trigger the broken
``api.v1.stats`` import. We achieve that by stubbing every leaf
in ``sys.modules`` before any ``from zaqorincore_server.api.v1
import ...`` statement runs.
"""

from __future__ import annotations

import importlib
import sys
import types

# Submodules of zaqorincore_server.api.v1 that ``api.v1.__init__``
# imports wholesale. We stub every one except ``agents_provision``
# (which we want to actually load).
_V1_LEAVES = (
    "agents",
    "agents_provision",
    "alerts",
    "audit",
    "audit_bots",
    "auth",
    "canary",
    "evidence",
    "events",
    "healthcheck",
    "hosts",
    "hunt",
    "ingest_cloudflare",
    "ingest_webhook",
    "rules_studio",
    "security",
    "sources",
    "stats",
    "stream",
    "version",
)


def _stub_module(name: str) -> types.ModuleType:
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m


# ─── Module-level work-around (runs before pytest collection) ───────────
# Drop any half-imported parent packages.
for k in list(sys.modules):
    if k.startswith("zaqorincore_server.api"):
        del sys.modules[k]

# Stub the top-level api package and its v1 subpackage so their
# ``__init__.py`` does not pull in the broken stats chain.
import zaqorincore_server  # noqa: F401,E402

_api_pkg = _stub_module("zaqorincore_server.api")
_api_pkg.__path__ = ["src/zaqorincore_server/api"]  # type: ignore[attr-defined]

_health_mod = _stub_module("zaqorincore_server.api.health")

_v1_pkg = _stub_module("zaqorincore_server.api.v1")
_v1_pkg.__path__ = ["src/zaqorincore_server/api/v1"]  # type: ignore[attr-defined]

# Stub every leaf except agents_provision.
for _leaf in _V1_LEAVES:
    if _leaf == "agents_provision":
        continue
    _stub_module(f"zaqorincore_server.api.v1.{_leaf}")

# Load the real agents_provision module now so the test files
# can `from zaqorincore_server.api.v1 import agents_provision`.
importlib.import_module("zaqorincore_server.api.v1.agents_provision")


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _noop():
    """No-op autouse fixture (kept so future per-test setup can go here)."""
    yield