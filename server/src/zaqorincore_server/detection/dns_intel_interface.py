"""DNS intel interface for T1583.001 domain acquisition detection.

Provides a small Protocol describing how the rule engine consumes
enrichment metadata (WHOIS, RDAP, registration age) and a stub
concrete client that operators can wire up against their preferred
WHOIS / RDAP backend.

This module contains NO live network calls. The ``WHOISRDAPClient``
class is a placeholder that returns empty results until a real
backend is configured via the ``WHOIS_RDAP_URL`` env var. This keeps
the detection pack shippable in air-gapped or restricted environments
while leaving a clean seam for the production implementation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class DomainIntel:
    """Enrichment metadata produced by a WHOIS / RDAP lookup.

    Attributes:
        domain_name: The queried second-level domain.
            ``"example.com"``, never with protocol or path.
        age_days: Days since the domain was registered. ``None`` when
            the backend could not determine the registration date.
        age_seconds: Seconds since registration, when known with
            sub-day precision. ``None`` when only day-level data is
            available.
        registrar: Registrar name, when disclosed. ``None`` otherwise.
        last_seen_days: Days since the domain was last queried by any
            monitored host. ``None`` when the cache has no record.
        is_legitimate_brand: True when the registrant matches a known
            protected brand (set by the brand_protection stage, not by
            the WHOIS backend itself).
    """

    domain_name: str
    age_days: int | None = None
    age_seconds: int | None = None
    registrar: str | None = None
    last_seen_days: int | None = None
    is_legitimate_brand: bool = False


@runtime_checkable
class DNSIntelClient(Protocol):
    """Lookup contract used by the rule engine.

    Concrete implementations may use WHOIS (port 43), RDAP (HTTPS),
    passive DNS feeds, or any combination thereof. The rule engine
    only relies on the synchronous ``lookup`` method returning a
    populated ``DomainIntel`` (or one with empty fields when the
    backend is unreachable).
    """

    def lookup(self, domain: str) -> DomainIntel:
        """Return enrichment metadata for ``domain``.

        Implementations MUST NOT raise on transient backend errors;
        they should return a ``DomainIntel`` with ``age_days=None``
        and ``registrar=None`` so the rule engine can degrade
        gracefully instead of missing the detection window.
        """
        ...


class WHOISRDAPClient:
    """Stub client wired to ``WHOIS_RDAP_URL``.

    The real implementation should issue RDAP ``https://<host>/domain/<fqdn>``
    requests and parse the ``events`` array (registration event)
    plus ``entities`` for the registrar name.

    Until a backend is configured this stub returns empty intel so
    the rule engine can run without network access during tests.
    """

    def __init__(self, base_url: str | None = None, timeout: float = 2.0) -> None:
        # Allow env override; never hard-code a credential or host.
        self._base_url: str | None = base_url or os.environ.get("WHOIS_RDAP_URL")
        self._timeout: float = timeout

    @property
    def base_url(self) -> str | None:
        return self._base_url

    def lookup(self, domain: str) -> DomainIntel:
        """Return empty intel.

        Replace with a real RDAP/WHOIS call once ``WHOIS_RDAP_URL`` is
        configured. Kept as a no-op so unit tests do not require
        network access and so the rule engine degrades cleanly when
        no backend is wired up.
        """
        return DomainIntel(domain_name=domain)


def default_client() -> DNSIntelClient:
    """Return the project-wide default DNS intel client.

    Operators can monkey-patch this in their deployment config to
    swap in a real backend without touching call sites.
    """
    return WHOISRDAPClient()