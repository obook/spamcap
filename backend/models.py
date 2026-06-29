"""Modèles Pydantic de l'API.

Ces modèles définissent le contrat JSON exposé par l'API : la requête
d'analyse en entrée et le résultat complet en sortie. Ils sont distincts des
dataclasses internes de `parser`, `resolver` et `detector` ; `analysis`
assemble ces dernières en :class:`AnalysisResult`.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """Charge utile de la requête d'analyse."""

    raw_headers: str = Field(
        ..., description="En-tête brut du courriel à analyser."
    )


class HopInfo(BaseModel):
    """Un saut du parcours, enrichi de sa résolution et de sa réputation."""

    hop_index: int
    ip: str | None
    from_host: str | None
    resolved_ip: str | None
    ip_version: int
    ptr: str | None
    has_reverse: bool | None
    country: str | None
    country_code: str | None
    city: str | None
    org: str | None
    timestamp: datetime | None
    delay_seconds: int | None
    is_private: bool
    dnsbl: dict[str, bool | None]


class AuthResult(BaseModel):
    """Résultats d'authentification SPF, DKIM et DMARC."""

    spf: str | None
    dkim: str | None
    dmarc: str | None
    spf_detail: str | None
    dkim_domain: str | None


class AnomalyItem(BaseModel):
    """Une anomalie détectée, avec sa sévérité et sa description lisible."""

    type: str
    severity: str
    description: str


class FilterVerdict(BaseModel):
    """Verdict du filtre anti-spam du fournisseur de réception, normalisé."""

    source: str | None
    is_spam: bool | None
    score: str | None
    details: list[str]


class AnalysisResult(BaseModel):
    """Résultat complet d'une analyse, renvoyé par POST /analyze."""

    hops: list[HopInfo]
    auth: AuthResult
    filter_verdict: FilterVerdict
    anomalies: list[AnomalyItem]
    verdict: str
    from_domain: str | None
    from_domain_created: str | None
    from_domain_updated: str | None
    from_domain_registrar: str | None
    to_domain: str | None
    from_address: str | None
    to_recipients: str | None
    cc_recipients: str | None
    subject: str | None
    date: str | None
    message_id: str | None
    return_path: str | None
    is_bulk: bool
    bulk_esp: str | None
    bulk_unsubscribe: str | None
    originating: HopInfo | None
    truncated: bool
    raw_size_bytes: int
    analyzed_size_bytes: int
    geoip_warning: str | None = None
