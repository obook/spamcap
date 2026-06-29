"""Aides de domaine et de texte pour la détection."""

from __future__ import annotations

import re
from datetime import datetime, timezone

# Reconnaît un domaine niché dans un texte (nom affiché), via une adresse ou
# un domaine nu.
_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_DOMAIN_IN_TEXT_RE = re.compile(
    r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b"
)


def first_group(pattern: str, text: str) -> str | None:
    """Renvoie le premier groupe capturé d'un motif, ou None."""

    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else None


def domain_part(address: str) -> str | None:
    """Renvoie le domaine d'une adresse déjà nettoyée, ou None."""

    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower()


def domain_in_text(text: str) -> str | None:
    """Extrait un domaine d'un texte libre : adresse, sinon domaine nu."""

    match = _EMAIL_IN_TEXT_RE.search(text)
    if match:
        return match.group(1).lower()
    match = _DOMAIN_IN_TEXT_RE.search(text)
    if match:
        return match.group(1).lower()
    return None


def registrable(host: str) -> str:
    """Domaine enregistrable grossier : les deux derniers labels du nom."""

    labels = host.strip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def parse_iso(value: str | None) -> datetime | None:
    """Analyse une date ISO 8601 et la rend toujours conscient du fuseau."""

    if not value:
        return None
    try:
        parsed_date = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed_date.tzinfo is None:
        return parsed_date.replace(tzinfo=timezone.utc)
    return parsed_date
