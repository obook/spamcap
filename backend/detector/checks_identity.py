"""Vérifications fondées sur l'identité : auth, filtre, domaine expéditeur."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parseaddr

from backend.emailutil import domain_of
from backend.parser import ParsedEmail

from .domains import domain_in_text, domain_part, parse_iso, registrable
from .models import (
    PUBLIC_WEBMAIL,
    RECENT_DOMAIN_DAYS,
    Anomaly,
    AuthResult,
    SEVERITY_MAJOR,
    SEVERITY_MINOR,
)


def check_auth(auth: AuthResult) -> list[Anomaly]:
    """Signale un échec ou une faiblesse de SPF, DKIM ou DMARC."""

    anomalies: list[Anomaly] = []

    if auth.spf == "fail":
        anomalies.append(
            Anomaly(
                "spf_fail",
                SEVERITY_MAJOR,
                "SPF en échec : l'expéditeur n'est pas autorisé.",
            )
        )
    elif auth.spf in {"softfail", "neutral"}:
        anomalies.append(
            Anomaly(
                "spf_softfail",
                SEVERITY_MINOR,
                f"SPF {auth.spf} : autorisation incertaine.",
            )
        )

    if auth.dkim == "fail":
        anomalies.append(
            Anomaly("dkim_fail", SEVERITY_MAJOR, "Signature DKIM invalide.")
        )

    if auth.dmarc == "fail":
        anomalies.append(
            Anomaly("dmarc_fail", SEVERITY_MAJOR, "DMARC en échec.")
        )

    return anomalies


def check_filter(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale un courriel que le filtre du fournisseur classe indésirable."""

    verdict = parsed.filter_verdict
    if verdict.is_spam:
        source = verdict.source or "Le filtre du fournisseur"
        score = f" ({verdict.score})" if verdict.score else ""
        return [
            Anomaly(
                "filter_spam",
                SEVERITY_MINOR,
                f"{source} classe ce courriel comme indésirable{score}.",
            )
        ]
    return []


def check_display_name(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale un nom affiché qui évoque un domaine autre que l'adresse."""

    name, address = parseaddr(parsed.from_header or "")
    from_domain = domain_part(address)
    if not name or not from_domain:
        return []

    claimed = domain_in_text(name)
    if claimed and registrable(claimed) != registrable(from_domain):
        return [
            Anomaly(
                "display_name_spoof",
                SEVERITY_MAJOR,
                f"Le nom affiché évoque {claimed} alors que l'adresse "
                f"réelle est {address}.",
            )
        ]
    return []


def check_lookalike_domain(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale un domaine expéditeur internationalisé (punycode)."""

    from_domain = domain_of(parsed.from_header)
    if not from_domain:
        return []

    if any(label.startswith("xn--") for label in from_domain.split(".")):
        return [
            Anomaly(
                "punycode_domain",
                SEVERITY_MINOR,
                f"Le domaine expéditeur ({from_domain}) est internationalisé "
                "(punycode), parfois utilisé pour imiter une marque.",
            )
        ]
    return []


def check_dmarc_alignment(
    parsed: ParsedEmail, auth: AuthResult
) -> list[Anomaly]:
    """Signale une signature DKIM valide pour un autre domaine.

    Quand DMARC passe, l'alignement est déjà garanti : on ne signale rien.
    """

    from_domain = domain_of(parsed.from_header)
    if not from_domain or auth.dmarc == "pass":
        return []

    signer = auth.dkim_domain
    misaligned = (
        auth.dkim == "pass"
        and signer
        and registrable(signer) != registrable(from_domain)
    )
    if misaligned:
        return [
            Anomaly(
                "dmarc_misalignment",
                SEVERITY_MINOR,
                f"Signature DKIM valide pour {signer}, différent du domaine "
                f"affiché {from_domain}, sans DMARC pour le contrôler.",
            )
        ]
    return []


def check_recent_domain(domain_created: str | None) -> list[Anomaly]:
    """Signale un domaine expéditeur créé très récemment."""

    created = parse_iso(domain_created)
    if created is None:
        return []

    age_days = (datetime.now(timezone.utc) - created).days
    if 0 <= age_days < RECENT_DOMAIN_DAYS:
        return [
            Anomaly(
                "recent_domain",
                SEVERITY_MINOR,
                f"Domaine expéditeur créé il y a {age_days} jours, "
                "possible hameçonnage.",
            )
        ]
    return []


def check_reply_to(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale une adresse de réponse sur un autre domaine que l'expéditeur.

    Ignoré sur un courriel de masse : une infolettre utilise légitimement une
    adresse de réponse d'un autre domaine.
    """

    if parsed.bulk.is_bulk:
        return []

    reply_domain = domain_of(parsed.reply_to)
    from_domain = domain_of(parsed.from_header)
    if not reply_domain or not from_domain:
        return []
    if registrable(reply_domain) == registrable(from_domain):
        return []
    return [_build_replyto_anomaly(reply_domain, from_domain)]


def _build_replyto_anomaly(reply_domain: str, from_domain: str) -> Anomaly:
    """Construit l'anomalie de réponse détournée.

    Toute réponse hors du domaine expéditeur est une alerte majeure. Le cas le
    plus grave (boîte gratuite) reçoit un message renforcé.
    """

    if registrable(reply_domain) in PUBLIC_WEBMAIL:
        return Anomaly(
            "replyto_webmail",
            SEVERITY_MAJOR,
            f"Les réponses seraient détournées vers une boîte gratuite "
            f"({reply_domain}), distincte de l'expéditeur {from_domain} : "
            f"motif classique d'usurpation.",
        )
    return Anomaly(
        "replyto_mismatch",
        SEVERITY_MAJOR,
        f"Les réponses iraient vers {reply_domain}, différent de "
        f"l'expéditeur {from_domain}.",
    )
