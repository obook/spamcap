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
    resolver._lookup_ptr = lambda ip: ("dns.google", True)
    resolver._lookup_geo = lambda ip: ("United States", "US", "Mountain View")
    resolver._lookup_org = lambda ip: "GOOGLE (AS15169)"

    result = resolver.resolve("8.8.8.8")

    assert result.ptr == "dns.google"
    assert result.has_reverse is True
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

    resolver._lookup_ptr = lambda ip: (None, None)
    resolver._lookup_geo = lambda ip: (None, None, None)
    resolver._lookup_org = fake_lookup

    resolver.resolve("8.8.8.8")
    resolver.resolve("8.8.8.8")

    assert calls["count"] == 1


def test_failed_lookups_degrade_to_none(resolver: Resolver) -> None:
    # Les helpers sous-jacents absorbent leurs erreurs et renvoient des valeurs vides.
    resolver._lookup_ptr = lambda ip: (None, None)
    resolver._lookup_geo = lambda ip: (None, None, None)
    resolver._lookup_org = lambda ip: None

    result = resolver.resolve("8.8.8.8")

    assert result.ptr is None
    assert result.has_reverse is None
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


def test_ptr_states(resolver: Resolver, monkeypatch) -> None:
    import dns.resolver

    class Answer:
        def __getitem__(self, index: int) -> str:
            return "mail.example.com."

    monkeypatch.setattr(resolver._dns, "resolve", lambda name, rdtype: Answer())
    assert resolver._lookup_ptr("8.8.8.8") == ("mail.example.com", True)

    def raise_nxdomain(name, rdtype):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(resolver._dns, "resolve", raise_nxdomain)
    assert resolver._lookup_ptr("8.8.8.8") == (None, False)

    def raise_timeout(name, rdtype):
        raise dns.resolver.LifetimeTimeout

    monkeypatch.setattr(resolver._dns, "resolve", raise_timeout)
    assert resolver._lookup_ptr("8.8.8.8") == (None, None)


def test_forward_lookup(resolver: Resolver, monkeypatch) -> None:
    class Answer:
        def __len__(self) -> int:
            return 1

        def __getitem__(self, index: int) -> str:
            return "212.27.48.10"

    monkeypatch.setattr(resolver._dns, "resolve", lambda host, record_type: Answer())
    assert resolver.forward_lookup("proxad.net") == "212.27.48.10"

    def raise_error(host, record_type):
        raise RuntimeError("dns down")

    monkeypatch.setattr(resolver._dns, "resolve", raise_error)
    assert resolver.forward_lookup("proxad.net") is None


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
