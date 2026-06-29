"""Détection de falsification et verdict de légitimité.

À partir d'un courriel analysé et de ses sauts résolus, ce module extrait les
résultats SPF, DKIM et DMARC, puis recherche les incohérences qui trahissent un
message usurpé : horodatages dans le désordre, relais privé glissé entre deux
relais publics, domaine expéditeur qui ne correspond pas au premier relais, et
(quand un résolveur MX est fourni) un premier saut qui n'est pas un serveur de
messagerie publié du domaine expéditeur.

La sortie est une liste ordonnée d'anomalies, chacune avec une sévérité, et un
verdict unique :

- ``LÉGITIME`` : aucune anomalie.
- ``SUSPECT`` : uniquement des anomalies mineures (SPF softfail, faible écart
  d'horodatage...).
- ``DOUTEUX`` : au moins une anomalie majeure (échec SPF/DKIM, IP privée
  insérée...).

La détection est pure, hormis la recherche MX optionnelle, qui est injectée pour
que la logique reste testable hors-ligne.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr

from backend.parser import ParsedEmail
from backend.resolver import ResolvedIP, is_private_ip

# Au-delà de cet écart entre deux sauts consécutifs, le délai paraît anormal.
MAX_PLAUSIBLE_GAP_SECONDS = 3600

# En deçà de cet age, le domaine expéditeur est jugé très récent, indice
# classique d'hameçonnage.
RECENT_DOMAIN_DAYS = 30

VERDICT_LEGITIMATE = "LÉGITIME"
VERDICT_SUSPECT = "SUSPECT"
VERDICT_DOUBTFUL = "DOUTEUX"

SEVERITY_MINOR = "minor"
SEVERITY_MAJOR = "major"

# Domaines de messagerie grand public (boites gratuites). Une adresse de reponse
# qui pointe vers l'un d'eux, alors que l'expediteur affiche un domaine
# d'organisation, est un motif classique d'usurpation (fraude au president) :
# les reponses partent vers une boite controlee par l'attaquant.
PUBLIC_WEBMAIL = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "outlook.fr",
        "hotmail.com",
        "hotmail.fr",
        "live.com",
        "live.fr",
        "msn.com",
        "yahoo.com",
        "yahoo.fr",
        "ymail.com",
        "icloud.com",
        "me.com",
        "aol.com",
        "gmx.com",
        "gmx.fr",
        "gmx.net",
        "mail.com",
        "proton.me",
        "protonmail.com",
        "zoho.com",
        "yandex.com",
        "yandex.ru",
        "free.fr",
        "orange.fr",
        "wanadoo.fr",
        "sfr.fr",
        "laposte.net",
    }
)

# Un appelable qui renvoie l'ensemble des IP servant de MX pour un domaine.
MxResolver = Callable[[str], set[str]]

# Reconnait un domaine niché dans un texte (nom affiché), via une adresse ou un
# domaine nu.
_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_DOMAIN_IN_TEXT_RE = re.compile(r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")


@dataclass
class AuthResult:
    """Résultats d'authentification extraits des en-têtes."""

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    spf_detail: str | None = None
    dkim_domain: str | None = None


@dataclass
class Anomaly:
    """Une incohérence détectée unique."""

    type: str
    severity: str
    description: str


@dataclass
class DetectionResult:
    """Résultat de la passe de détection."""

    auth: AuthResult
    anomalies: list[Anomaly] = field(default_factory=list)
    verdict: str = VERDICT_LEGITIMATE


def parse_auth(parsed: ParsedEmail) -> AuthResult:
    """Extrait les résultats SPF, DKIM et DMARC des en-têtes d'authentification."""

    combined = parsed.authentication_results or ""
    auth = AuthResult(
        spf=_first_group(r"\bspf=(\w+)", combined),
        dkim=_first_group(r"\bdkim=(\w+)", combined),
        dmarc=_first_group(r"\bdmarc=(\w+)", combined),
        dkim_domain=_first_group(r"header\.d=([^\s;]+)", combined),
    )

    # Received-SPF est la source de repli pour le résultat SPF et son détail.
    if parsed.received_spf:
        if auth.spf is None:
            auth.spf = _first_group(r"^(\w+)", parsed.received_spf)
        auth.spf_detail = parsed.received_spf

    # Un en-tête DKIM-Signature seul indique le domaine signataire même quand le
    # champ Authentication-Results l'omet.
    if auth.dkim_domain is None and parsed.dkim_signatures:
        auth.dkim_domain = _first_group(r"\bd=([^\s;]+)", parsed.dkim_signatures[0])

    return auth


def detect(
    parsed: ParsedEmail,
    resolved: list[ResolvedIP] | None = None,
    mx_resolver: MxResolver | None = None,
    domain_created: str | None = None,
) -> DetectionResult:
    """Exécute toutes les vérifications et renvoie les anomalies et un verdict global.

    ``resolved`` est parallèle à ``parsed.hops`` par index et fournit les noms
    PTR ; s'il est omis, les vérifications fondées sur le PTR sont ignorées.
    ``mx_resolver`` active la vérification MX du premier saut ; s'il est omis,
    cette vérification est ignorée.
    """

    auth = parse_auth(parsed)
    anomalies: list[Anomaly] = []

    anomalies.extend(_check_auth(auth))
    anomalies.extend(_check_filter(parsed))
    anomalies.extend(_check_display_name(parsed))
    anomalies.extend(_check_lookalike_domain(parsed))
    anomalies.extend(_check_recent_domain(domain_created))
    anomalies.extend(_check_dmarc_alignment(parsed, auth))
    anomalies.extend(_check_reply_to(parsed))
    anomalies.extend(_check_timestamps(parsed))
    anomalies.extend(_check_private_injection(parsed))
    anomalies.extend(_check_from_relay(parsed, resolved))
    anomalies.extend(_check_first_hop_mx(parsed, mx_resolver))

    return DetectionResult(auth=auth, anomalies=anomalies, verdict=_verdict(anomalies))


def _check_auth(auth: AuthResult) -> list[Anomaly]:
    anomalies: list[Anomaly] = []

    if auth.spf == "fail":
        anomalies.append(
            Anomaly("spf_fail", SEVERITY_MAJOR, "SPF en échec : l'expéditeur n'est pas autorisé.")
        )
    elif auth.spf in {"softfail", "neutral"}:
        anomalies.append(
            Anomaly("spf_softfail", SEVERITY_MINOR, f"SPF {auth.spf} : autorisation incertaine.")
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


def _check_filter(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale un courriel que le filtre du fournisseur classe comme indésirable."""

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


def _check_timestamps(parsed: ParsedEmail) -> list[Anomaly]:
    anomalies: list[Anomaly] = []

    previous = None
    for hop in parsed.hops:
        if hop.timestamp is None:
            continue
        if previous is not None:
            delta = (hop.timestamp - previous).total_seconds()
            if delta < 0:
                anomalies.append(
                    Anomaly(
                        "timestamp_inversion",
                        SEVERITY_MAJOR,
                        "Horodatage incohérent : un saut précède le saut antérieur.",
                    )
                )
            elif delta > MAX_PLAUSIBLE_GAP_SECONDS:
                anomalies.append(
                    Anomaly(
                        "timestamp_gap",
                        SEVERITY_MINOR,
                        f"Délai inhabituel entre deux sauts ({int(delta)} s).",
                    )
                )
        previous = hop.timestamp

    return anomalies


def _check_private_injection(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale une IP privée placée entre deux relais publics."""

    anomalies: list[Anomaly] = []
    hops = parsed.hops

    for index in range(1, len(hops) - 1):
        current = hops[index].from_ip
        before = hops[index - 1].from_ip
        after = hops[index + 1].from_ip
        if not (current and before and after):
            continue
        if is_private_ip(current) and not is_private_ip(before) and not is_private_ip(after):
            anomalies.append(
                Anomaly(
                    "private_ip_injected",
                    SEVERITY_MAJOR,
                    f"IP privée insérée entre deux relais publics ({current}).",
                )
            )

    return anomalies


def _check_from_relay(
    parsed: ParsedEmail, resolved: list[ResolvedIP] | None
) -> list[Anomaly]:
    """Signale un écart entre le domaine From et le PTR du premier relais."""

    if not resolved:
        return []

    from_domain = _domain_of(parsed.from_header)
    first_ptr = resolved[0].ptr if resolved else None
    if not from_domain or not first_ptr:
        return []

    if _registrable(first_ptr) != _registrable(from_domain):
        return [
            Anomaly(
                "from_relay_mismatch",
                SEVERITY_MINOR,
                f"Le domaine expéditeur ({from_domain}) diffère du premier relais ({first_ptr}).",
            )
        ]

    return []


def _check_first_hop_mx(
    parsed: ParsedEmail, mx_resolver: MxResolver | None
) -> list[Anomaly]:
    """Signale un premier saut absent des MX publiés du domaine expéditeur."""

    if mx_resolver is None or not parsed.hops:
        return []

    from_domain = _domain_of(parsed.from_header)
    first_ip = parsed.hops[0].from_ip
    if not from_domain or not first_ip:
        return []

    mx_ips = mx_resolver(from_domain)
    if not mx_ips:
        # Recherche en échec ou aucun MX : preuves insuffisantes pour signaler.
        return []

    if first_ip not in mx_ips:
        return [
            Anomaly(
                "mx_mismatch",
                SEVERITY_MINOR,
                f"Premier relais ({first_ip}) absent des serveurs MX de {from_domain}.",
            )
        ]

    return []


def _check_display_name(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale un nom affiché qui évoque un domaine autre que l'adresse réelle."""

    name, address = parseaddr(parsed.from_header or "")
    from_domain = _domain_part(address)
    if not name or not from_domain:
        return []

    claimed = _domain_in_text(name)
    if claimed and _registrable(claimed) != _registrable(from_domain):
        return [
            Anomaly(
                "display_name_spoof",
                SEVERITY_MAJOR,
                f"Le nom affiché évoque {claimed} alors que l'adresse réelle est {address}.",
            )
        ]
    return []


def _check_lookalike_domain(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale un domaine expéditeur internationalisé (punycode)."""

    from_domain = _domain_of(parsed.from_header)
    if not from_domain:
        return []

    if any(label.startswith("xn--") for label in from_domain.split(".")):
        return [
            Anomaly(
                "punycode_domain",
                SEVERITY_MINOR,
                f"Le domaine expéditeur ({from_domain}) est internationalisé (punycode), "
                "parfois utilisé pour imiter une marque.",
            )
        ]
    return []


def _check_dmarc_alignment(parsed: ParsedEmail, auth: AuthResult) -> list[Anomaly]:
    """Signale une signature DKIM valide pour un domaine autre que l'expéditeur.

    Quand DMARC passe, l'alignement est déjà garanti : on ne signale rien.
    """

    from_domain = _domain_of(parsed.from_header)
    if not from_domain or auth.dmarc == "pass":
        return []

    signer = auth.dkim_domain
    if auth.dkim == "pass" and signer and _registrable(signer) != _registrable(from_domain):
        return [
            Anomaly(
                "dmarc_misalignment",
                SEVERITY_MINOR,
                f"Signature DKIM valide pour {signer}, différent du domaine affiché "
                f"{from_domain}, sans DMARC pour le contrôler.",
            )
        ]
    return []


def _check_recent_domain(domain_created: str | None) -> list[Anomaly]:
    """Signale un domaine expéditeur créé très récemment."""

    created = _parse_iso(domain_created)
    if created is None:
        return []

    age_days = (datetime.now(timezone.utc) - created).days
    if 0 <= age_days < RECENT_DOMAIN_DAYS:
        return [
            Anomaly(
                "recent_domain",
                SEVERITY_MINOR,
                f"Domaine expéditeur créé il y a {age_days} jours, possible hameçonnage.",
            )
        ]
    return []


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed_date = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed_date.tzinfo is None:
        return parsed_date.replace(tzinfo=timezone.utc)
    return parsed_date


def _check_reply_to(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale une adresse de réponse sur un domaine autre que l'expéditeur.

    Ignoré sur un courriel de masse : une infolettre utilise légitimement une
    adresse de réponse d'un autre domaine.
    """

    if parsed.bulk.is_bulk:
        return []

    reply_domain = _domain_of(parsed.reply_to)
    from_domain = _domain_of(parsed.from_header)
    if not reply_domain or not from_domain:
        return []
    if _registrable(reply_domain) == _registrable(from_domain):
        return []

    # Toute adresse de reponse sur un autre domaine que l'expediteur est une
    # alerte majeure : les reponses partiraient ailleurs que chez l'expediteur
    # affiche. Le cas le plus grave (boite gratuite) recoit un message renforce.
    if _registrable(reply_domain) in PUBLIC_WEBMAIL:
        return [
            Anomaly(
                "replyto_webmail",
                SEVERITY_MAJOR,
                f"Les réponses seraient détournées vers une boite gratuite "
                f"({reply_domain}), distincte de l'expéditeur {from_domain} : "
                f"motif classique d'usurpation.",
            )
        ]
    return [
        Anomaly(
            "replyto_mismatch",
            SEVERITY_MAJOR,
            f"Les réponses iraient vers {reply_domain}, différent de "
            f"l'expéditeur {from_domain}.",
        )
    ]


def _verdict(anomalies: list[Anomaly]) -> str:
    if any(a.severity == SEVERITY_MAJOR for a in anomalies):
        return VERDICT_DOUBTFUL
    if anomalies:
        return VERDICT_SUSPECT
    return VERDICT_LEGITIMATE


def _first_group(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else None


def _domain_of(address_header: str | None) -> str | None:
    if not address_header:
        return None
    _, email_address = parseaddr(address_header)
    if "@" not in email_address:
        return None
    return email_address.rsplit("@", 1)[1].lower()


def _domain_part(address: str) -> str | None:
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower()


def _domain_in_text(text: str) -> str | None:
    """Extrait un domaine d'un texte libre : adresse de courriel, sinon domaine nu."""

    match = _EMAIL_IN_TEXT_RE.search(text)
    if match:
        return match.group(1).lower()
    match = _DOMAIN_IN_TEXT_RE.search(text)
    if match:
        return match.group(1).lower()
    return None


def _registrable(host: str) -> str:
    """Domaine enregistrable grossier : les deux derniers labels d'un nom d'hôte."""

    labels = host.strip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()
