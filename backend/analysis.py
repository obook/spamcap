"""Orchestration de l'analyse d'un en-tête de courriel.

Enchaîne l'analyse (`parser`), la résolution de chaque saut (`resolver`, avec
vérification DNSBL) et la détection de falsification (`detector`), puis
assemble le tout en un :class:`AnalysisResult`. Aucun courriel n'est
conservé : tout vit en mémoire le temps de la requête.
"""

from __future__ import annotations

from backend.detector import detect
from backend.emailutil import domain_of
from backend.models import (
    AnalysisResult,
    AnomalyItem,
    AuthResult,
    FilterVerdict,
    HopInfo,
)
from backend.parser import parse_email
from backend.resolver import ResolvedIP, Resolver


def build_analysis(raw: str, resolver: Resolver) -> AnalysisResult:
    """Assemble le résultat d'analyse à partir des modules internes."""

    parsed = parse_email(raw)
    hops, resolved_hops = _resolve_hops(parsed, resolver)

    from_domain = domain_of(parsed.from_header)
    if from_domain:
        dates = resolver.domain_dates(from_domain)
    else:
        dates = (None, None, None)
    domain_created, domain_updated, domain_registrar = dates

    detection = detect(
        parsed, resolved=resolved_hops, domain_created=domain_created
    )
    originating = _build_originating(parsed.originating_ip, resolver)

    return _assemble_result(
        parsed=parsed,
        hops=hops,
        detection=detection,
        originating=originating,
        from_domain=from_domain,
        domain_created=domain_created,
        domain_updated=domain_updated,
        domain_registrar=domain_registrar,
        geoip_warning=resolver.geoip_warning,
    )


def _resolve_hops(
    parsed, resolver: Resolver
) -> tuple[list[HopInfo], list[ResolvedIP]]:
    """Résout chaque saut et renvoie les vues d'interface et de détection."""

    hops: list[HopInfo] = []
    resolved_hops: list[ResolvedIP] = []
    previous_timestamp = None
    no_dnsbl: dict[str, bool | None] = {"spamcop": None, "spamhaus": None}

    for hop in parsed.hops:
        resolved_ip = None
        ptr = None
        has_reverse = None
        dnsbl = no_dnsbl

        if hop.from_ip:
            resolved = resolver.resolve(hop.from_ip)
            dnsbl = resolver.dnsbl_check(hop.from_ip)
            ptr = resolved.ptr
            has_reverse = resolved.has_reverse
            # Le détecteur ne voit que la résolution de l'IP d'origine.
            resolved_hops.append(resolved)
            # Une IP privée n'a pas de géo, mais son nom d'hôte porte souvent
            # un domaine public : on le géolocalise, à titre indicatif.
            if resolved.is_private and hop.from_host:
                domain_geo = _geo_from_domain(hop.from_host, resolver)
                if domain_geo:
                    resolved.country = domain_geo.country
                    resolved.country_code = domain_geo.country_code
        else:
            # Aucune IP dans l'en-tête : le détecteur ne dispose de rien.
            resolved_hops.append(ResolvedIP(ip="", ip_version=0))
            resolved = ResolvedIP(ip="", ip_version=0)
            # On géolocalise le nom d'hôte via DNS direct, à titre indicatif.
            if hop.from_host:
                derived = resolver.forward_lookup(hop.from_host)
                if derived:
                    resolved = resolver.resolve(derived)
                    resolved_ip = derived

        delay = None
        if hop.timestamp is not None and previous_timestamp is not None:
            delay = int((hop.timestamp - previous_timestamp).total_seconds())
        if hop.timestamp is not None:
            previous_timestamp = hop.timestamp

        hops.append(
            HopInfo(
                hop_index=hop.index,
                ip=hop.from_ip,
                from_host=hop.from_host,
                resolved_ip=resolved_ip,
                ip_version=resolved.ip_version,
                ptr=ptr,
                has_reverse=has_reverse,
                country=resolved.country,
                country_code=resolved.country_code,
                city=resolved.city,
                org=resolved.org,
                timestamp=hop.timestamp,
                delay_seconds=delay,
                is_private=resolved.is_private if hop.from_ip else False,
                dnsbl=dnsbl,
            )
        )

    return hops, resolved_hops


def _assemble_result(
    *,
    parsed,
    hops: list[HopInfo],
    detection,
    originating: HopInfo | None,
    from_domain: str | None,
    domain_created: str | None,
    domain_updated: str | None,
    domain_registrar: str | None,
    geoip_warning: str | None,
) -> AnalysisResult:
    """Réunit toutes les pièces dans le modèle d'API plat."""

    return AnalysisResult(
        hops=hops,
        auth=AuthResult(
            spf=detection.auth.spf,
            dkim=detection.auth.dkim,
            dmarc=detection.auth.dmarc,
            spf_detail=detection.auth.spf_detail,
            dkim_domain=detection.auth.dkim_domain,
        ),
        filter_verdict=FilterVerdict(
            source=parsed.filter_verdict.source,
            is_spam=parsed.filter_verdict.is_spam,
            score=parsed.filter_verdict.score,
            details=parsed.filter_verdict.details,
        ),
        anomalies=[
            AnomalyItem(
                type=a.type, severity=a.severity, description=a.description
            )
            for a in detection.anomalies
        ],
        verdict=detection.verdict,
        from_domain=from_domain,
        from_domain_created=domain_created,
        from_domain_updated=domain_updated,
        from_domain_registrar=domain_registrar,
        to_domain=domain_of(parsed.to_header),
        from_address=parsed.from_header,
        to_recipients=parsed.to_header,
        cc_recipients=parsed.cc_header,
        subject=parsed.subject,
        date=parsed.date_header,
        message_id=parsed.message_id,
        return_path=parsed.return_path,
        is_bulk=parsed.bulk.is_bulk,
        bulk_esp=parsed.bulk.esp,
        bulk_unsubscribe=parsed.bulk.unsubscribe,
        originating=originating,
        truncated=parsed.truncated,
        raw_size_bytes=parsed.raw_size_bytes,
        analyzed_size_bytes=parsed.analyzed_size_bytes,
        geoip_warning=geoip_warning,
    )


def _geo_from_domain(host: str, resolver: Resolver) -> ResolvedIP | None:
    """Géolocalise le domaine enregistrable d'un nom d'hôte, à titre indicatif.

    Utile pour un saut en IP privée : le domaine public (par exemple
    proxad.net) révèle le pays de l'opérateur, faute de mieux.
    """

    labels = host.strip(".").split(".")
    if len(labels) < 2:
        return None
    domain = ".".join(labels[-2:])
    ip = resolver.forward_lookup(domain)
    if not ip:
        return None
    resolved = resolver.resolve(ip)
    if resolved.is_private or not resolved.country:
        return None
    return resolved


def _build_originating(ip: str | None, resolver: Resolver) -> HopInfo | None:
    """Construit le nœud du poste expéditeur, même pour une IP privée."""

    if not ip:
        return None
    resolved = resolver.resolve(ip)
    return HopInfo(
        hop_index=-1,
        ip=ip,
        from_host=None,
        resolved_ip=None,
        ip_version=resolved.ip_version,
        ptr=resolved.ptr,
        has_reverse=resolved.has_reverse,
        country=resolved.country,
        country_code=resolved.country_code,
        city=resolved.city,
        org=resolved.org,
        timestamp=None,
        delay_seconds=None,
        is_private=resolved.is_private,
        dnsbl=resolver.dnsbl_check(ip),
    )
