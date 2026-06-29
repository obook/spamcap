"""Tests unitaires des verifications DNSBL dans backend.resolver."""

from __future__ import annotations

import dns.resolver

from backend.resolver import Resolver, dnsbl_query_name


def test_ipv4_query_name_reverses_octets() -> None:
    assert dnsbl_query_name("1.2.3.4", "bl.spamcop.net") == "4.3.2.1.bl.spamcop.net"


def test_ipv6_query_name_reverses_nibbles() -> None:
    name = dnsbl_query_name("2001:db8::1", "zen.spamhaus.org")

    assert name.endswith(".zen.spamhaus.org")
    prefix = name.removesuffix(".zen.spamhaus.org")
    nibbles = prefix.split(".")
    assert len(nibbles) == 32
    assert all(len(label) == 1 for label in nibbles)


def test_private_ip_is_unknown_on_every_zone() -> None:
    resolver = Resolver(geoip_path=None)

    assert resolver.dnsbl_check("10.0.0.1") == {"spamcop": None, "spamhaus": None}


def test_listed_ip_returns_true(monkeypatch) -> None:
    resolver = Resolver(geoip_path=None)
    monkeypatch.setattr(resolver._dns, "resolve", lambda name, rdtype: ["127.0.0.2"])

    result = resolver.dnsbl_check("8.8.8.8")

    assert result == {"spamcop": True, "spamhaus": True}


def test_unlisted_ip_returns_false(monkeypatch) -> None:
    resolver = Resolver(geoip_path=None)

    def raise_nxdomain(name, rdtype):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(resolver._dns, "resolve", raise_nxdomain)

    result = resolver.dnsbl_check("8.8.8.8")

    assert result == {"spamcop": False, "spamhaus": False}


def test_timeout_returns_unknown(monkeypatch) -> None:
    resolver = Resolver(geoip_path=None)

    def raise_timeout(name, rdtype):
        raise dns.resolver.LifetimeTimeout

    monkeypatch.setattr(resolver._dns, "resolve", raise_timeout)

    result = resolver.dnsbl_check("8.8.8.8")

    assert result == {"spamcop": None, "spamhaus": None}
