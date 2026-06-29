"""Analyse des en-têtes de courriel : interface publique du paquet.

Le paquet est découpé par responsabilité (modèles, extraction des relais,
filtres, en-têtes), mais expose une surface plate identique à l'ancien
module : importez depuis ``backend.parser`` directement.
"""

from .core import parse_email, split_and_truncate
from .models import (
    BODY_PREVIEW_CHARS,
    MAX_INPUT_BYTES,
    MICROSOFT_SPAM_SCL,
    BulkInfo,
    FilterVerdict,
    ParsedEmail,
    RawHop,
    SplitResult,
)

__all__ = [
    "parse_email",
    "split_and_truncate",
    "ParsedEmail",
    "RawHop",
    "FilterVerdict",
    "BulkInfo",
    "SplitResult",
    "MAX_INPUT_BYTES",
    "BODY_PREVIEW_CHARS",
    "MICROSOFT_SPAM_SCL",
]
