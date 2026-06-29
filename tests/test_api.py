"""Tests de l'API FastAPI.

Le resolveur est remplace par une doublure pour rester hors-ligne : aucune
requete DNS, GeoIP ou WHOIS reelle n'est emise.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app, get_resolver
from backend.parser import MAX_INPUT_BYTES
from backend.resolver import ResolvedIP

HEADER = "\n".join(
    [
        "Received: from mx.recipient.com (mx.recipient.com [203.0.113.10])",
        "\tby mail.recipient.com (Postfix) with ESMTPS id 4ABCDE",
        "\tfor <user@recipient.com>; Tue, 01 Jan 2026 10:00:05 +0000",
        "Received: from smtp.sender.com (smtp.sender.com [198.51.100.20])",
        "\tby mx.recipient.com (Postfix) with ESMTP id 1ZZZZZ",
        "\tfor <user@recipient.com>; Tue, 01 Jan 2026 10:00:00 +0000",
        "From: Alice <alice@sender.com>",
        "Subject: Bonjour",
        "Authentication-Results: mx.recipient.com; spf=pass; dkim=pass; dmarc=pass",
    ]
)


class FakeResolver:
    """Doublure de Resolver qui renvoie des donnees fixes, sans reseau."""

    geoip_warning = None

    def resolve(self, ip: str) -> ResolvedIP:
        return ResolvedIP(
            ip=ip,
            ip_version=4,
            ptr="relay.sender.com",
            country="France",
            city="Paris",
            org="Example Org (AS64500)",
            is_private=False,
        )

    def dnsbl_check(self, ip: str) -> dict[str, bool | None]:
        return {"spamcop": False, "spamhaus": False}

    def forward_lookup(self, host: str) -> str | None:
        return None

    def domain_dates(self, domain: str) -> tuple[str | None, str | None, str | None]:
        return None, None, None

    def close(self) -> None:
        pass


@pytest.fixture
def client() -> TestClient:
    app.dependency_overrides[get_resolver] = lambda: FakeResolver()
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()


def test_health(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_returns_resolved_hops(client: TestClient) -> None:
    response = client.post("/analyze", json={"raw_headers": HEADER})

    assert response.status_code == 200
    body = response.json()
    assert len(body["hops"]) == 2
    assert body["hops"][0]["country"] == "France"
    assert body["hops"][0]["dnsbl"] == {"spamcop": False, "spamhaus": False}
    assert body["verdict"] in {"LÉGITIME", "SUSPECT", "DOUTEUX"}
    assert body["from_domain"] == "sender.com"
    assert body["subject"] == "Bonjour"


def test_analyze_rejects_oversized_input(client: TestClient) -> None:
    oversized = "A" * (MAX_INPUT_BYTES + 1)

    response = client.post("/analyze", json={"raw_headers": oversized})

    assert response.status_code == 413
