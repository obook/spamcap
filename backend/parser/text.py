"""Petites aides de texte partagées par l'analyseur."""

from __future__ import annotations

import re


def collapse(value: str) -> str:
    """Réduit repliement et sauts de ligne en espaces simples."""

    return " ".join(value.split())


def group(pattern: str, text: str) -> str | None:
    """Renvoie le premier groupe capturé d'un motif, ou None."""

    if not text:
        return None
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1) if match else None


def to_int(value: str | None) -> int | None:
    """Convertit en entier de façon tolérante, ou None."""

    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
