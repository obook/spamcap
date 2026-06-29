"""Aides communes sur les adresses de courriel."""

from __future__ import annotations

from email.utils import parseaddr


def domain_of(address_header: str | None) -> str | None:
    """Extrait le domaine d'un en-tête d'adresse (From, To)."""

    if not address_header:
        return None
    _, email_address = parseaddr(address_header)
    if "@" not in email_address:
        return None
    return email_address.rsplit("@", 1)[1].lower()
