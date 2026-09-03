"""T1583.001 domain-acquisition detection helpers.

Exposes the DNS intel interface stub and the brand protection
(Levenshtein) helpers used by the Sigma rules in
``server/rules/builtin/mitre_attack/T1583_001_*.yml``.
"""

from __future__ import annotations

from zaqorincore_server.detection.brand_protection import (
    DEFAULT_PROTECTED_BRANDS,
    TyposquatMatch,
    check_typosquat,
    first_typosquat,
    levenshtein,
    protected_brands,
)
from zaqorincore_server.detection.dns_intel_interface import (
    DNSIntelClient,
    DomainIntel,
    WHOISRDAPClient,
    default_client,
)

__all__ = [
    "DEFAULT_PROTECTED_BRANDS",
    "DNSIntelClient",
    "DomainIntel",
    "TyposquatMatch",
    "WHOISRDAPClient",
    "check_typosquat",
    "default_client",
    "first_typosquat",
    "levenshtein",
    "protected_brands",
]