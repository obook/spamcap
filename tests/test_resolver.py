"""Tests unitaires de backend.resolver.

Ces tests restent hors-ligne : les recherches réseau (PTR, GeoIP, WHOIS) sont
soit ignorées sur les adresses privées, soit remplacées par des doublures.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.resolver import Resolver, ResolvedIP, is_private_ip


@pytest.fixture
def resolver() -> Resolver:
    # Aucune base GeoIP : le lecteur reste absent et aucun fichier n'est ouvert.
    return Resolver(geoip_path=None)


def test_private_ipv4_is_labeled_and_skips_network(resolver: Resolver) -> None:
    result = resolver.resolve("192.168.1.10")

    assert result == ResolvedIP(
        ip="192.168.1.10", ip_version=4, is_private=True
    )


def test_ipv6_loopback_is_private(resolver: Resolver) -> None:
    result = resolver.resolve("::1")

    assert result.is_private is True
    assert result.ip_version == 6


def test_invalid_ip_yields_version_zero(resolver: Resolver) -> None:
    result = resolver.resolve("not-an-ip")

    assert result.ip_version == 0
    assert result.is_private is False


def test_is_private_helper() -> None:
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.5.5") is True
    assert is_private_ip("fe80::1") is True
    assert is_private_ip("8.8.8.8") is False


def test_public_ip_uses_lookups(resolver: Resolver) -> None:
    resolver._lookup_ptr = lambda ip: "dns.google"
    resolver._lookup_geo = lambda ip: ("United States", "US", "Mountain View")
    resolver._lookup_org = lambda ip: "GOOGLE (AS15169)"

    result = resolver.resolve("8.8.8.8")

    assert result.ptr == "dns.google"
    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.city == "Mountain View"
    assert result.org == "GOOGLE (AS15169)"
    assert result.is_private is False


def test_whois_result_is_cached(resolver: Resolver) -> None:
    calls = {"count": 0}

    def fake_lookup(ip: str) -> str:
        calls["count"] += 1
        return "ACME (AS64500)"

    resolver._lookup_ptr = lambda ip: None
    resolver._lookup_geo = lambda ip: (None, None, None)
    resolver._lookup_org = fake_lookup

    resolver.resolve("8.8.8.8")
    resolver.resolve("8.8.8.8")

    assert calls["count"] == 1


def test_failed_lookups_degrade_to_none(resolver: Resolver) -> None:
    # Les helpers sous-jacents absorbent leurs erreurs et renvoient des valeurs vides.
    resolver._lookup_ptr = lambda ip: None
    resolver._lookup_geo = lambda ip: (None, None, None)
    resolver._lookup_org = lambda ip: None

    result = resolver.resolve("8.8.8.8")

    assert result.ptr is None
    assert result.country is None
    assert result.org is None


def test_org_falls_back_to_network_name(resolver: Resolver, monkeypatch) -> None:
    # En IPv6, le RDAP renvoie souvent asn=NA mais garde le nom du reseau.
    import backend.resolver as resolver_module

    class FakeIPWhois:
        def __init__(self, ip: str) -> None:
            pass

        def lookup_rdap(self, depth: int = 0) -> dict:
            return {"asn": "NA", "asn_description": "NA", "network": {"name": "MSFT"}}

    monkeypatch.setattr(resolver_module, "IPWhois", FakeIPWhois)

    assert resolver._lookup_org("2603:10a6:20b:61a::17") == "MSFT"


def test_missing_geoip_database_sets_warning() -> None:
    resolver = Resolver(geoip_path=Path("/nonexistent/GeoLite2-City.mmdb"))

    assert resolver.geoip_available is False
    assert resolver.geoip_warning is not None
    assert resolver._lookup_geo("8.8.8.8") == (None, None, None)


def test_geoip_reader_is_used_when_present(resolver: Resolver) -> None:
    fake_record = SimpleNamespace(
        country=SimpleNamespace(name="France", iso_code="FR"),
        city=SimpleNamespace(name="Paris"),
    )
    resolver._geoip_reader = SimpleNamespace(city=lambda ip: fake_record)

    assert resolver._lookup_geo("8.8.8.8") == ("France", "FR", "Paris")
