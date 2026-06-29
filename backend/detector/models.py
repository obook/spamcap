"""Modèles, constantes et seuils de la détection de falsification."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

# Au-delà de cet écart entre deux sauts consécutifs, le délai paraît anormal.
MAX_PLAUSIBLE_GAP_SECONDS = 3600

# En deçà de cet âge, le domaine expéditeur est jugé très récent, indice
# classique d'hameçonnage.
RECENT_DOMAIN_DAYS = 30

VERDICT_LEGITIMATE = "LÉGITIME"
VERDICT_SUSPECT = "SUSPECT"
VERDICT_DOUBTFUL = "DOUTEUX"

SEVERITY_MINOR = "minor"
SEVERITY_MAJOR = "major"

# Domaines de messagerie grand public (boîtes gratuites). Une adresse de
# réponse qui pointe vers l'un d'eux, alors que l'expéditeur affiche un
# domaine d'organisation, est un motif classique d'usurpation (fraude au
# président) : les réponses partent vers une boîte contrôlée par l'attaquant.
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
