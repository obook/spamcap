"""Analyse et troncature des en-têtes de courriel.

Ce module transforme le texte brut collé par l'utilisateur en une vue
structurée du parcours du message. Il n'effectue aucun accès réseau : la
résolution (PTR, GeoIP, WHOIS, DNSBL) et la détection de falsification vivent
dans leurs propres modules.

Deux responsabilités ici :

1. Troncature. Un courriel complet peut peser plusieurs mégaoctets, alors que
   seuls les en-têtes comptent pour l'analyse du parcours. On sépare en-têtes et
   corps sur la première ligne vide (RFC 5322) et on ne conserve qu'un court
   aperçu du corps.
2. Extraction. On lit la chaîne "Received:", on l'inverse en ordre chronologique
   (de l'expéditeur au destinataire), puis on extrait les IP, les horodatages et
   les en-têtes d'authentification et d'information utilisés en aval.

L'analyse est volontairement tolérante : un champ mal formé ne doit jamais lever
d'exception.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email.header import decode_header, make_header
from email.message import Message
from email.parser import HeaderParser
from email.utils import parsedate_to_datetime

# Au-delà de cette taille, le contenu est signalé comme tronqué à l'appelant. La
# couche API rejette séparément les charges utiles trop volumineuses (HTTP 413).
MAX_INPUT_BYTES = 200 * 1024

# Volume de corps conservé, uniquement pour que l'utilisateur confirme le bon
# courriel.
BODY_PREVIEW_CHARS = 500

# Un littéral IPv6 dans un champ Received: peut porter un préfixe "IPv6:" et se
# trouve généralement entre crochets, comme "[IPv6:2001:db8::1]".
_BRACKETED_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_IPV6_TOKEN_RE = re.compile(r"[0-9A-Fa-f:]{2,}")

# Un nom d'hote : des labels alphanumériques séparés par des points.
_HOST_RE = re.compile(r"(?<![\w.-])([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?![\w-])")

# Le DNS inverse du pair, dans la forme "from HELO (rdns [IP])" : plus
# identifiant que le nom annoncé (HELO).
_RDNS_RE = re.compile(r"\(([A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+)\s*\[")


@dataclass
class RawHop:
    """Un relais unique extrait d'un champ "Received:".

    "from_ip" est la source du saut et l'adresse sur laquelle se concentrent la
    résolution et la détection en aval ; "by_ip" est le serveur récepteur.
    """

    index: int
    from_ip: str | None
    by_ip: str | None
    timestamp: datetime | None
    raw: str
    from_host: str | None = None


# À partir de ce Spam Confidence Level, Microsoft considère le courriel comme
# indésirable (échelle -1 à 9).
MICROSOFT_SPAM_SCL = 5


@dataclass
class FilterVerdict:
    """Verdict du filtre anti-spam du fournisseur de réception, normalisé.

    Chaque fournisseur (Microsoft 365, SpamAssassin, etc.) appose son propre
    verdict via des en-têtes propriétaires. On les normalise ici en une vue
    commune, seule source de verdict pour un courriel interne ou SPF, DKIM et
    DMARC sont absents par construction.

    `details` conserve les signaux bruts lisibles (par exemple "SCL 1", "BCL 0").
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
class _SplitResult:
    headers: str
    body_preview: str
    truncated: bool
    raw_size_bytes: int
    analyzed_size_bytes: int


def split_and_truncate(raw: str) -> _SplitResult:
    """Sépare en-têtes et corps sur la première ligne vide et abandonne le corps.

    Seul le bloc d'en-têtes est analysé. Le corps est réduit à un court aperçu
    que l'API ne reçoit jamais ; il existe pour que l'interface puisse l'afficher.
    """

    raw_size = len(raw.encode("utf-8"))

    # La ligne vide qui termine le bloc d'en-têtes peut utiliser LF ou CRLF.
    parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    headers = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    analyzed_size = len(headers.encode("utf-8"))
    body_preview = body[:BODY_PREVIEW_CHARS]

    truncated = analyzed_size < raw_size or raw_size > MAX_INPUT_BYTES

    return _SplitResult(
        headers=headers,
        body_preview=body_preview,
        truncated=truncated,
        raw_size_bytes=raw_size,
        analyzed_size_bytes=analyzed_size,
    )


def parse_email(raw: str) -> ParsedEmail:
    """Analyse le texte brut d'un courriel en un :class:`ParsedEmail`.

    Ne lève jamais d'exception sur une entrée mal formée : les champs
    inanalysables donnent des valeurs ``None`` plutôt que des exceptions.
    """

    split = split_and_truncate(raw)
    message = HeaderParser().parsestr(split.headers)

    # get_all renvoie les champs Received dans l'ordre du document, le plus
    # récent en premier. On inverse pour que le saut 0 soit le serveur d'origine.
    received_fields = message.get_all("Received", [])
    hops: list[RawHop] = []
    for index, value in enumerate(reversed(received_fields)):
        main, timestamp_text = _split_on_timestamp(value)
        from_clause = _extract_clause(main, "from", ("by",))
        by_clause = _extract_clause(main, "by", ("with", "id", "for", "via"))
        hops.append(
            RawHop(
                index=index,
                from_ip=_first_ip(from_clause),
                by_ip=_first_ip(by_clause),
                timestamp=_parse_date(timestamp_text),
                raw=_collapse(value),
                from_host=_first_host(from_clause),
            )
        )

    return ParsedEmail(
        hops=hops,
        from_header=_decode(message.get("From")),
        to_header=_decode(message.get("To")),
        cc_header=_decode(message.get("Cc")),
        reply_to=_decode(message.get("Reply-To")),
        return_path=_decode(message.get("Return-Path")),
        subject=_decode(message.get("Subject")),
        date_header=_decode(message.get("Date")),
        message_id=_decode(message.get("Message-ID")),
        originating_ip=_extract_originating(message),
        bulk=_extract_bulk(message),
        authentication_results=_join(message.get_all("Authentication-Results")),
        received_spf=_join(message.get_all("Received-SPF")),
        dkim_signatures=[_collapse(v) for v in message.get_all("DKIM-Signature", [])],
        filter_verdict=_detect_filter(message),
        body_preview=split.body_preview,
        truncated=split.truncated,
        raw_size_bytes=split.raw_size_bytes,
        analyzed_size_bytes=split.analyzed_size_bytes,
    )


def _split_on_timestamp(received_value: str) -> tuple[str, str]:
    """Sépare un champ Received en sa partie parcours et son horodatage final.

    La RFC 5322 place la date après le dernier point-virgule du champ.
    """

    collapsed = _collapse(received_value)
    if ";" in collapsed:
        route, timestamp = collapsed.rsplit(";", 1)
        return route, timestamp.strip()
    return collapsed, ""


def _extract_clause(route: str, keyword: str, stop_words: tuple[str, ...]) -> str:
    """Renvoie le texte d'une clause "from"/"by" jusqu'au mot-clé suivant."""

    stop = "|".join(rf"\b{word}\b" for word in stop_words)
    pattern = rf"\b{keyword}\b\s+(.*?)(?:{stop}|$)"
    match = re.search(pattern, route, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _first_ip(text: str) -> str | None:
    """Extrait la première IP valide d'une clause, IPv4 ou IPv6.

    Les littéraux entre crochets sont privilégiés, car c'est là que les serveurs
    inscrivent l'adresse réelle. Les correspondances libres sont validées pour
    éviter de confondre, par exemple, un numéro de version avec une IPv4.
    """

    if not text:
        return None

    for match in _BRACKETED_IP_RE.finditer(text):
        ip = _valid_ip(match.group(1))
        if ip:
            return ip

    for match in _IPV4_RE.finditer(text):
        ip = _valid_ip(match.group(0))
        if ip:
            return ip

    for token in _IPV6_TOKEN_RE.findall(text):
        if token.count(":") >= 2:
            ip = _valid_ip(token)
            if ip:
                return ip

    return None


def _first_host(text: str) -> str | None:
    """Extrait le premier nom d'hote d'une clause, en ignorant les IP.

    Utile quand un saut n'a pas d'IP exploitable : le nom d'hote du serveur reste
    une information de parcours (par exemple un relais interne Exchange).
    """

    if not text:
        return None
    # Le DNS inverse entre parenthèses identifie mieux le pair que le HELO.
    reverse = _RDNS_RE.search(text)
    if reverse:
        return reverse.group(1).rstrip(".").lower()
    for match in _HOST_RE.finditer(text):
        host = match.group(1)
        if _valid_ip(host):
            continue
        return host.rstrip(".").lower()
    return None


def _valid_ip(candidate: str) -> str | None:
    """Renvoie l'adresse normalisée si ``candidate`` est une IP valide, sinon None."""

    try:
        return str(ipaddress.ip_address(candidate.strip()))
    except ValueError:
        return None


def _parse_date(text: str) -> datetime | None:
    """Analyse une date RFC 5322, renvoie None en cas d'échec."""

    if not text:
        return None
    try:
        return parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None


def _decode(value: str | None) -> str | None:
    """Décode un en-tête encodé RFC 2047 (par exemple un Subject en UTF-8)."""

    if value is None:
        return None
    try:
        return str(make_header(decode_header(value)))
    except (ValueError, LookupError):
        return _collapse(value)


def _join(values: list[str] | None) -> str | None:
    """Concatène des champs répétés en une chaîne, ou None s'ils sont absents."""

    if not values:
        return None
    return "\n".join(_collapse(v) for v in values)


def _collapse(value: str) -> str:
    """Réduit les espaces de repliement et les retours à la ligne en espaces simples."""

    return " ".join(value.split())


def _extract_originating(message: Message) -> str | None:
    """Extrait l'IP du poste expéditeur depuis les en-têtes clients.

    Présente surtout quand le courriel part d'un webmail ou d'un script. Une IP
    privée révèle un poste interne (intranet) de l'expéditeur.
    """

    for header in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP", "X-Client-IP"):
        value = message.get(header)
        if value:
            ip = _first_ip(value)
            if ip:
                return ip
    return None


def _extract_bulk(message: Message) -> BulkInfo:
    """Détecte un courriel de masse (infolettre) et sa plateforme d'envoi."""

    list_id = _collapse(message.get("List-Id") or "") or None
    list_unsubscribe = message.get("List-Unsubscribe")
    is_bulk = bool(list_id or list_unsubscribe)

    return BulkInfo(
        is_bulk=is_bulk,
        list_id=list_id,
        unsubscribe=_first_unsubscribe(list_unsubscribe),
        esp=_detect_esp(message),
    )


def _detect_esp(message: Message) -> str | None:
    """Identifie la plateforme d'envoi (X-Mailer, sinon suffixe du Feedback-ID)."""

    mailer = message.get("X-Mailer")
    if mailer:
        return _collapse(mailer)
    feedback = message.get("Feedback-ID")
    if feedback and ":" in feedback:
        return feedback.rsplit(":", 1)[-1].strip() or None
    return None


def _first_unsubscribe(value: str | None) -> str | None:
    """Extrait un lien de désabonnement (URL ou mailto) de List-Unsubscribe."""

    if not value:
        return None
    url = re.search(r"<(https?://[^>]+)>", value)
    if url:
        return url.group(1)
    mailto = re.search(r"<(mailto:[^>]+)>", value)
    if mailto:
        return mailto.group(1)
    return None


def _detect_filter(message: Message) -> FilterVerdict:
    """Détecte le fournisseur de filtrage et normalise son verdict.

    Les détecteurs sont essayés dans l'ordre ; le premier qui reconnait ses
    en-têtes l'emporte. Ajouter un fournisseur revient à écrire une fonction de
    plus et à l'ajouter à cette liste.
    """

    for detect_one in (_microsoft_filter, _spamassassin_filter, _proxad_filter):
        verdict = detect_one(message)
        if verdict is not None:
            return verdict
    return FilterVerdict()


def _microsoft_filter(message: Message) -> FilterVerdict | None:
    """Normalise les en-têtes anti-spam de Microsoft 365 / Exchange.

    SCL (Spam Confidence Level) et AuthAs ont des en-têtes dédiés ; BCL (Bulk
    Complaint Level) est niché dans ``X-Microsoft-Antispam`` ; SFV est dans
    ``X-Forefront-Antispam-Report``, qui porte aussi parfois SCL en repli.
    """

    scl = _to_int(message.get("X-MS-Exchange-Organization-SCL"))
    auth_as = message.get("X-MS-Exchange-Organization-AuthAs") or None

    antispam = _collapse(message.get("X-Microsoft-Antispam") or "")
    bcl = _to_int(_group(r"\bBCL:(-?\d+)", antispam))

    forefront = _collapse(message.get("X-Forefront-Antispam-Report") or "")
    if scl is None:
        scl = _to_int(_group(r"\bSCL:(-?\d+)", forefront))
    sfv = _group(r"\bSFV:(\w+)", forefront)

    if scl is None and bcl is None and sfv is None and auth_as is None:
        return None

    is_spam: bool | None = None
    if scl is not None:
        is_spam = scl >= MICROSOFT_SPAM_SCL
    if sfv == "SPM":
        is_spam = True

    details: list[str] = []
    if scl is not None:
        details.append(f"SCL {scl}")
    if bcl is not None:
        details.append(f"BCL {bcl}")
    if sfv:
        details.append(f"SFV {sfv}")
    if auth_as:
        details.append(f"AuthAs {auth_as}")

    score = f"SCL {scl}" if scl is not None else None
    return FilterVerdict(source="Microsoft 365", is_spam=is_spam, score=score, details=details)


def _spamassassin_filter(message: Message) -> FilterVerdict | None:
    """Normalise les en-têtes SpamAssassin (X-Spam-*), très répandus.

    ``X-Spam-Flag: YES`` tranche le verdict ; ``X-Spam-Status`` porte le mot-clé
    et le score (``score=2.3 required=5.0``) ; ``X-Spam-Score`` est un repli.
    """

    flag = message.get("X-Spam-Flag")
    status = _collapse(message.get("X-Spam-Status") or "")
    score_header = message.get("X-Spam-Score")

    if not (flag or status or score_header):
        return None

    is_spam: bool | None = None
    if flag:
        is_spam = flag.strip().upper() == "YES"
    elif status:
        verdict_word = _group(r"^(\w+)", status)
        if verdict_word:
            is_spam = verdict_word.lower() == "yes"

    raw_score = _group(r"score=(-?[\d.]+)", status) or (
        score_header.strip() if score_header else None
    )
    required = _group(r"required=(-?[\d.]+)", status)
    if raw_score and required:
        score = f"score {raw_score}/{required}"
    elif raw_score:
        score = f"score {raw_score}"
    else:
        score = None

    details: list[str] = []
    if is_spam is not None:
        details.append("spam" if is_spam else "non-spam")
    if score:
        details.append(score)

    return FilterVerdict(source="SpamAssassin", is_spam=is_spam, score=score, details=details)


def _proxad_filter(message: Message) -> FilterVerdict | None:
    """Normalise le verdict du filtre de Free / Proxad (`X-ProXaD-SC`).

    Format typique : ``state=HAM:CommercialEmailGeneric score=17``.
    """

    value = _collapse(message.get("X-ProXaD-SC") or "")
    if not value:
        return None

    state = _group(r"state=([A-Za-z]+)", value)
    category = _group(r"state=[A-Za-z]+:(\S+)", value)
    score = _group(r"score=(-?\d+)", value)

    is_spam: bool | None = None
    if state:
        is_spam = state.upper() == "SPAM"

    details: list[str] = []
    if state:
        details.append(f"{state}:{category}" if category else state)
    if score:
        details.append(f"score {score}")

    return FilterVerdict(
        source="Proxad/Free",
        is_spam=is_spam,
        score=f"score {score}" if score else None,
        details=details,
    )


def _group(pattern: str, text: str) -> str | None:
    """Renvoie le premier groupe capturé d'un motif, ou None."""

    if not text:
        return None
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else None


def _to_int(value: str | None) -> int | None:
    """Convertit en entier de façon tolérante, ou None."""

    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
