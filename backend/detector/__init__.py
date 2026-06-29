"""Détection de falsification : interface publique du paquet.

Le paquet est découpé par responsabilité (modèles, aides de domaine,
vérifications d'identité, vérifications de parcours, orchestration), mais
expose une surface plate : importez depuis ``backend.detector`` directement.
"""

from .core import detect, parse_auth
from .models import (
    MAX_PLAUSIBLE_GAP_SECONDS,
    PUBLIC_WEBMAIL,
    RECENT_DOMAIN_DAYS,
    Anomaly,
    AuthResult,
    DetectionResult,
    MxResolver,
    SEVERITY_MAJOR,
    SEVERITY_MINOR,
    VERDICT_DOUBTFUL,
    VERDICT_LEGITIMATE,
    VERDICT_SUSPECT,
)

__all__ = [
    "detect",
    "parse_auth",
    "AuthResult",
    "Anomaly",
    "DetectionResult",
    "MxResolver",
    "PUBLIC_WEBMAIL",
    "RECENT_DOMAIN_DAYS",
    "MAX_PLAUSIBLE_GAP_SECONDS",
    "SEVERITY_MINOR",
    "SEVERITY_MAJOR",
    "VERDICT_LEGITIMATE",
    "VERDICT_SUSPECT",
    "VERDICT_DOUBTFUL",
]
