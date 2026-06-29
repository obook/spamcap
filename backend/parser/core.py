"""Analyse et troncature des en-têtes de courriel.

Ce module transforme le texte brut collé par l'utilisateur en une vue
structurée du parcours du message. Il n'effectue aucun accès réseau : la
résolution (PTR, GeoIP, WHOIS, DNSBL) et la détection de falsification
vivent dans leurs propres modules.

Deux responsabilités ici :

1. Troncature. Un courriel complet peut peser plusieurs mégaoctets, alors
   que seuls les en-têtes comptent. On sépare en-têtes et corps sur la
   première ligne vide (RFC 5322) et on ne garde qu'un court aperçu du corps.
2. Extraction. On lit la chaîne "Received:", on l'inverse en ordre
   chronologique, puis on extrait les IP, les horodatages et les en-têtes
   d'authentification et d'information utilisés en aval.

L'analyse est volontairement tolérante : un champ mal formé ne doit jamais
lever d'exception.
"""

from __future__ import annotations

import re
from email.parser import HeaderParser

from .filters import detect_filter
from .headers import decode, extract_bulk, extract_originating, join
from .hops import build_hops
from .models import (
    BODY_PREVIEW_CHARS,
    MAX_INPUT_BYTES,
    ParsedEmail,
    SplitResult,
)
from .text import collapse


def split_and_truncate(raw: str) -> SplitResult:
    """Sépare en-têtes et corps sur la première ligne vide.

    Seul le bloc d'en-têtes est analysé. Le corps est réduit à un court aperçu
    que l'API ne reçoit jamais ; il sert seulement à l'affichage.
    """

    raw_size = len(raw.encode("utf-8"))

    # La ligne vide qui termine le bloc d'en-têtes peut utiliser LF ou CRLF.
    parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    headers = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    analyzed_size = len(headers.encode("utf-8"))
    body_preview = body[:BODY_PREVIEW_CHARS]

    truncated = analyzed_size < raw_size or raw_size > MAX_INPUT_BYTES

    return SplitResult(
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

    return ParsedEmail(
        hops=build_hops(message),
        from_header=decode(message.get("From")),
        to_header=decode(message.get("To")),
        cc_header=decode(message.get("Cc")),
        reply_to=decode(message.get("Reply-To")),
        return_path=decode(message.get("Return-Path")),
        subject=decode(message.get("Subject")),
        date_header=decode(message.get("Date")),
        message_id=decode(message.get("Message-ID")),
        originating_ip=extract_originating(message),
        bulk=extract_bulk(message),
        authentication_results=join(message.get_all("Authentication-Results")),
        received_spf=join(message.get_all("Received-SPF")),
        dkim_signatures=[
            collapse(v) for v in message.get_all("DKIM-Signature", [])
        ],
        filter_verdict=detect_filter(message),
        body_preview=split.body_preview,
        truncated=split.truncated,
        raw_size_bytes=split.raw_size_bytes,
        analyzed_size_bytes=split.analyzed_size_bytes,
    )
