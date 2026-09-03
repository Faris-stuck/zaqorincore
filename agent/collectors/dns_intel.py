"""Stub DNS intel collector for T1583.001 detection (cycle 6, v3.2.0).

The full ZaqorinCore agent is implemented in Go (see ``agent/cmd/``
and ``agent/internal/``). This stub exists only to document the
collector contract for the Python-side Sigma rules and to provide a
small Python entry point for tests that exercise the log -> rule ->
alert path without bringing up the Go agent.

Production deployments will run the Go collector that pipes zeek_dns
and zeek_http events into the rule engine; this stub is intentionally
a no-op when imported outside the test harness.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class CollectorConfig:
    """Configuration for the (stub) DNS intel collector.

    Attributes:
        whois_rdap_url: Backend URL for RDAP/WHOIS lookups. Operators
            must populate this via the ``WHOIS_RDAP_URL`` env var;
            no default is committed so secrets never enter git.
        poll_interval_sec: How often the collector should poll the
            backend. Stub-only; the Go collector drives itself on
            the zeek log stream.
    """

    whois_rdap_url: str | None
    poll_interval_sec: int = 60


def load_config() -> CollectorConfig:
    """Build a ``CollectorConfig`` from the environment.

    Reads ``WHOIS_RDAP_URL`` (no default) and
    ``WHOIS_POLL_INTERVAL_SEC`` (default 60). Never logs the URL
    value to avoid leaking internal hostnames.
    """
    return CollectorConfig(
        whois_rdap_url=os.environ.get("WHOIS_RDAP_URL"),
        poll_interval_sec=int(os.environ.get("WHOIS_POLL_INTERVAL_SEC", "60")),
    )


def collect_once(_config: CollectorConfig) -> int:
    """Stub collect loop body.

    Returns the number of enriched events emitted. The stub returns
    0 because the real collection happens in the Go agent. Tests
    that import this module assert the stub is wired correctly
    without exercising any network code.
    """
    _LOG.debug("dns_intel stub collect_once invoked (no-op)")
    return 0