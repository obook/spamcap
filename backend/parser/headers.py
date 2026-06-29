"""Décodage des en-têtes et indices d'origine et de courriel de masse."""

from __future__ import annotations

import re
from email.header import decode_header, make_header
from email.message import Message

from .hops import first_ip
from .models import BulkInfo
from .text import collapse


def decode(value: str | None) -> str | None:
    """Décode un en-tête encodé RFC 2047 (par exemple un Subject en UTF-8)."""

    if value is None:
        return None
    try:
        return str(make_header(decode_header(value)))
    except (ValueError, LookupError):
        return collapse(value)


def join(values: list[str] | None) -> str | None:
    """Concatène des champs répétés, ou None s'ils sont absents."""

    if not values:
        return None
    return "\n".join(collapse(v) for v in values)


def extract_originating(message: Message) -> str | None:
    """Extrait l'IP du poste expéditeur depuis les en-têtes clients.

    Présente surtout quand le courriel part d'un webmail ou d'un script. Une
    IP privée révèle un poste interne (intranet) de l'expéditeur.
    """

    clients = ("X-Originating-IP", "X-Sender-IP", "X-Source-IP", "X-Client-IP")
    for header in clients:
        value = message.get(header)
        if value:
            ip = first_ip(value)
            if ip:
                return ip
    return None


def extract_bulk(message: Message) -> BulkInfo:
    """Détecte un courriel de masse (infolettre) et sa plateforme d'envoi."""

    list_id = collapse(message.get("List-Id") or "") or None
    list_unsubscribe = message.get("List-Unsubscribe")
    is_bulk = bool(list_id or list_unsubscribe)

    return BulkInfo(
        is_bulk=is_bulk,
        list_id=list_id,
        unsubscribe=_first_unsubscribe(list_unsubscribe),
        esp=_detect_esp(message),
    )


def _detect_esp(message: Message) -> str | None:
    """Identifie la plateforme d'envoi (X-Mailer, sinon Feedback-ID)."""

    mailer = message.get("X-Mailer")
    if mailer:
        return collapse(mailer)
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
