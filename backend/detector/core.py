"""Détection de falsification et verdict de légitimité.

À partir d'un courriel analysé et de ses sauts résolus, ce module extrait
les résultats SPF, DKIM et DMARC, puis recherche les incohérences qui
trahissent un message usurpé : horodatages dans le désordre, relais privé
glissé entre deux relais publics, domaine expéditeur qui ne correspond pas
au premier relais, et (quand un résolveur MX est fourni) un premier saut qui
n'est pas un serveur de messagerie publié du domaine expéditeur.

La sortie est une liste ordonnée d'anomalies, chacune avec une sévérité, et
un verdict unique :

- ``LÉGITIME`` : aucune anomalie.
- ``SUSPECT`` : uniquement des anomalies mineures.
- ``DOUTEUX`` : au moins une anomalie majeure.

La détection est pure, hormis la recherche MX optionnelle, injectée pour que
la logique reste testable hors-ligne.
"""

from __future__ import annotations

from backend.parser import ParsedEmail
from backend.resolver import ResolvedIP

from .checks_identity import (
    check_auth,
    check_display_name,
    check_dmarc_alignment,
    check_filter,
    check_lookalike_domain,
    check_recent_domain,
    check_reply_to,
)
from .checks_routing import (
    check_first_hop_mx,
    check_from_relay,
    check_private_injection,
    check_timestamps,
)
from .domains import first_group
from .models import (
    Anomaly,
    AuthResult,
    DetectionResult,
    MxResolver,
    SEVERITY_MAJOR,
    VERDICT_DOUBTFUL,
    VERDICT_LEGITIMATE,
    VERDICT_SUSPECT,
)


def parse_auth(parsed: ParsedEmail) -> AuthResult:
    """Extrait SPF, DKIM et DMARC des en-têtes d'authentification."""

    combined = parsed.authentication_results or ""
    auth = AuthResult(
        spf=first_group(r"\bspf=(\w+)", combined),
        dkim=first_group(r"\bdkim=(\w+)", combined),
        dmarc=first_group(r"\bdmarc=(\w+)", combined),
        dkim_domain=first_group(r"header\.d=([^\s;]+)", combined),
    )

    # Received-SPF est la source de repli pour le résultat SPF et son détail.
    if parsed.received_spf:
        if auth.spf is None:
            auth.spf = first_group(r"^(\w+)", parsed.received_spf)
        auth.spf_detail = parsed.received_spf

    # Un en-tête DKIM-Signature seul indique le domaine signataire même quand
    # le champ Authentication-Results l'omet.
    if auth.dkim_domain is None and parsed.dkim_signatures:
        auth.dkim_domain = first_group(
            r"\bd=([^\s;]+)", parsed.dkim_signatures[0]
        )

    return auth


def detect(
    parsed: ParsedEmail,
    resolved: list[ResolvedIP] | None = None,
    mx_resolver: MxResolver | None = None,
    domain_created: str | None = None,
) -> DetectionResult:
    """Exécute toutes les vérifications et renvoie les anomalies et un verdict.

    ``resolved`` est parallèle à ``parsed.hops`` par index et fournit les noms
    PTR ; s'il est omis, les vérifications fondées sur le PTR sont ignorées.
    ``mx_resolver`` active la vérification MX du premier saut ; s'il est omis,
    cette vérification est ignorée.
    """

    auth = parse_auth(parsed)
    anomalies: list[Anomaly] = []

    anomalies.extend(check_auth(auth))
    anomalies.extend(check_filter(parsed))
    anomalies.extend(check_display_name(parsed))
    anomalies.extend(check_lookalike_domain(parsed))
    anomalies.extend(check_recent_domain(domain_created))
    anomalies.extend(check_dmarc_alignment(parsed, auth))
    anomalies.extend(check_reply_to(parsed))
    anomalies.extend(check_timestamps(parsed))
    anomalies.extend(check_private_injection(parsed))
    anomalies.extend(check_from_relay(parsed, resolved))
    anomalies.extend(check_first_hop_mx(parsed, mx_resolver))

    return DetectionResult(
        auth=auth, anomalies=anomalies, verdict=_verdict(anomalies)
    )


def _verdict(anomalies: list[Anomaly]) -> str:
    """Déduit le verdict global de la pire sévérité présente."""

    if any(a.severity == SEVERITY_MAJOR for a in anomalies):
        return VERDICT_DOUBTFUL
    if anomalies:
        return VERDICT_SUSPECT
    return VERDICT_LEGITIMATE
