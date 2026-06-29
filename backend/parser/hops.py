"""Extraction des relais "Received:" et des IP/hôtes qu'ils portent."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from email.message import Message
from email.utils import parsedate_to_datetime

from .models import RawHop
from .text import collapse

# Un littéral IPv6 dans un champ Received: peut porter un préfixe "IPv6:" et
# se trouve généralement entre crochets, comme "[IPv6:2001:db8::1]".
_BRACKETED_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_IPV6_TOKEN_RE = re.compile(r"[0-9A-Fa-f:]{2,}")

# Un nom d'hôte : des labels alphanumériques séparés par des points.
_HOST_RE = re.compile(
    r"(?<![\w.-])([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?![\w-])"
)

# Le DNS inverse du pair, dans la forme "from HELO (rdns [IP])" : plus
# identifiant que le nom annoncé (HELO).
_RDNS_RE = re.compile(r"\(([A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+)\s*\[")


def build_hops(message: Message) -> list[RawHop]:
    """Construit la liste des sauts à partir des champs "Received:".

    get_all renvoie les champs Received dans l'ordre du document, le plus
    récent en premier. On inverse pour que le saut 0 soit le serveur d'origine.
    """

    received_fields = message.get_all("Received", [])
    hops: list[RawHop] = []
    for index, value in enumerate(reversed(received_fields)):
        route, timestamp_text = _split_on_timestamp(value)
        from_clause = _extract_clause(route, "from", ("by",))
        by_clause = _extract_clause(route, "by", ("with", "id", "for", "via"))
        hops.append(
            RawHop(
                index=index,
                from_ip=first_ip(from_clause),
                by_ip=first_ip(by_clause),
                timestamp=parse_date(timestamp_text),
                raw=collapse(value),
                from_host=first_host(from_clause),
            )
        )
    return hops


def _split_on_timestamp(received_value: str) -> tuple[str, str]:
    """Sépare un champ Received en sa partie parcours et son horodatage final.

    La RFC 5322 place la date après le dernier point-virgule du champ.
    """

    collapsed = collapse(received_value)
    if ";" in collapsed:
        route, timestamp = collapsed.rsplit(";", 1)
        return route, timestamp.strip()
    return collapsed, ""


def _extract_clause(
    route: str, keyword: str, stop_words: tuple[str, ...]
) -> str:
    """Renvoie le texte d'une clause "from"/"by" jusqu'au mot-clé suivant."""

    stop = "|".join(rf"\b{word}\b" for word in stop_words)
    pattern = rf"\b{keyword}\b\s+(.*?)(?:{stop}|$)"
    match = re.search(pattern, route, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def first_ip(text: str) -> str | None:
    """Extrait la première IP valide d'une clause, IPv4 ou IPv6.

    Les littéraux entre crochets sont privilégiés, car c'est là que les
    serveurs inscrivent l'adresse réelle. Les correspondances libres sont
    validées pour ne pas confondre un numéro de version avec une IPv4.
    """

    if not text:
        return None

    for match in _BRACKETED_IP_RE.finditer(text):
        ip = valid_ip(match.group(1))
        if ip:
            return ip

    for match in _IPV4_RE.finditer(text):
        ip = valid_ip(match.group(0))
        if ip:
            return ip

    for token in _IPV6_TOKEN_RE.findall(text):
        if token.count(":") >= 2:
            ip = valid_ip(token)
            if ip:
                return ip

    return None


def first_host(text: str) -> str | None:
    """Extrait le premier nom d'hôte d'une clause, en ignorant les IP.

    Utile quand un saut n'a pas d'IP exploitable : le nom d'hôte du serveur
    reste une information de parcours (par exemple un relais interne Exchange).
    """

    if not text:
        return None
    # Le DNS inverse entre parenthèses identifie mieux le pair que le HELO.
    reverse = _RDNS_RE.search(text)
    if reverse:
        return reverse.group(1).rstrip(".").lower()
    for match in _HOST_RE.finditer(text):
        host = match.group(1)
        if valid_ip(host):
            continue
        return host.rstrip(".").lower()
    return None


def valid_ip(candidate: str) -> str | None:
    """Renvoie l'adresse normalisée si candidate est une IP, sinon None."""

    try:
        return str(ipaddress.ip_address(candidate.strip()))
    except ValueError:
        return None


def parse_date(text: str) -> datetime | None:
    """Analyse une date RFC 5322, renvoie None en cas d'échec."""

    if not text:
        return None
    try:
        return parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
