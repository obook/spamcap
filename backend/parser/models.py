"""Modèles de données et constantes de l'analyseur d'en-têtes.

Regroupe les dataclasses produites par l'analyse (un saut, un verdict de
filtre, les indices de courriel de masse, le résultat complet) et les
constantes de seuil. Aucun comportement ici : seulement des structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Au-delà de cette taille, le contenu est signalé comme tronqué à l'appelant.
# La couche API rejette séparément les charges utiles trop volumineuses (413).
MAX_INPUT_BYTES = 200 * 1024

# Volume de corps conservé, uniquement pour que l'utilisateur confirme le bon
# courriel.
BODY_PREVIEW_CHARS = 500

# À partir de ce Spam Confidence Level, Microsoft considère le courriel comme
# indésirable (échelle -1 à 9).
MICROSOFT_SPAM_SCL = 5


@dataclass
class RawHop:
    """Un relais unique extrait d'un champ "Received:".

    "from_ip" est la source du saut et l'adresse sur laquelle se concentrent
    la résolution et la détection en aval ; "by_ip" est le serveur récepteur.
    """

    index: int
    from_ip: str | None
    by_ip: str | None
    timestamp: datetime | None
    raw: str
    from_host: str | None = None


@dataclass
class FilterVerdict:
    """Verdict du filtre anti-spam du fournisseur de réception, normalisé.

    Chaque fournisseur (Microsoft 365, SpamAssassin, etc.) appose son propre
    verdict via des en-têtes propriétaires. On les normalise ici en une vue
    commune, seule source de verdict pour un courriel interne où SPF, DKIM et
    DMARC sont absents par construction.

    "details" conserve les signaux bruts lisibles (par exemple "SCL 1").
    """

    source: str | None = None
    is_spam: bool | None = None
    score: str | None = None
    details: list[str] = field(default_factory=list)


@dataclass
class BulkInfo:
    """Indices de courriel de masse (infolettre, liste de diffusion)."""

    is_bulk: bool = False
    list_id: str | None = None
    unsubscribe: str | None = None
    esp: str | None = None


@dataclass
class ParsedEmail:
    """Résultat structuré de l'analyse de l'entrée brute."""

    hops: list[RawHop] = field(default_factory=list)
    from_header: str | None = None
    to_header: str | None = None
    cc_header: str | None = None
    reply_to: str | None = None
    return_path: str | None = None
    subject: str | None = None
    date_header: str | None = None
    message_id: str | None = None
    originating_ip: str | None = None
    authentication_results: str | None = None
    received_spf: str | None = None
    dkim_signatures: list[str] = field(default_factory=list)
    filter_verdict: FilterVerdict = field(default_factory=FilterVerdict)
    bulk: BulkInfo = field(default_factory=BulkInfo)
    body_preview: str = ""
    truncated: bool = False
    raw_size_bytes: int = 0
    analyzed_size_bytes: int = 0


@dataclass
class SplitResult:
    """En-têtes isolés du corps, avec les tailles mesurées."""

    headers: str
    body_preview: str
    truncated: bool
    raw_size_bytes: int
    analyzed_size_bytes: int
