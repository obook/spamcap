"""Application FastAPI de SpamCap.

Point d'entree du service. Expose deux routes :

- ``POST /analyze`` : recoit un en-tete brut, renvoie un :class:`AnalysisResult`
  complet (parcours resolu, reputation DNSBL, anomalies, verdict).
- ``GET /health`` : sonde de supervision.

L'orchestration enchaine l'analyse (`parser`), la resolution de chaque saut
(`resolver`, avec verification DNSBL) et la detection de falsification
(`detector`). Aucun courriel n'est conserve : tout vit en memoire le temps de la
requete.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Iterator
from email.utils import parseaddr
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend import parser
from backend.detector import detect
from backend.models import (
    AnalysisResult,
    AnalyzeRequest,
    AnomalyItem,
    AuthResult,
    FilterVerdict,
    HopInfo,
)
from backend.resolver import ResolvedIP, Resolver

# Origines autorisees pour le frontend en developpement local.
ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Plafonnement simple : nombre maximal de requetes par client sur la fenetre.
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0

app = FastAPI(
    title="SpamCap",
    description="Analyseur d'en-têtes de courriel.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Historique des appels par client, pour le plafonnement en memoire.
_request_history: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    """Plafonne le nombre de requetes par client sur une fenetre glissante."""

    client = request.client.host if request.client else "inconnu"
    now = time.monotonic()
    history = _request_history[client]

    while history and now - history[0] > RATE_LIMIT_WINDOW_SECONDS:
        history.popleft()

    if len(history) >= RATE_LIMIT_REQUESTS:
        return JSONResponse(
            status_code=429,
            content={"detail": "Trop de requêtes. Reessayez dans un instant."},
        )

    history.append(now)
    return await call_next(request)


def get_resolver() -> Iterator[Resolver]:
    """Fournit un resolveur dedie a la requete.

    Une instance par requete garantit que le cache WHOIS n'est jamais partage
    entre les analyses de plusieurs utilisateurs.
    """

    resolver = Resolver()
    try:
        yield resolver
    finally:
        resolver.close()


@app.get("/health")
def health() -> dict[str, str]:
    """Sonde de supervision."""

    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult)
def analyze(
    request: AnalyzeRequest, resolver: Resolver = Depends(get_resolver)
) -> AnalysisResult:
    """Analyse un en-tete brut et renvoie le resultat complet."""

    raw = request.raw_headers
    if len(raw.encode("utf-8")) > parser.MAX_INPUT_BYTES:
        raise HTTPException(
            status_code=413,
            detail="En-tête trop volumineux. Seuls les en-têtes sont nécessaires.",
        )

    return build_analysis(raw, resolver)


def build_analysis(raw: str, resolver: Resolver) -> AnalysisResult:
    """Assemble le resultat d'analyse a partir des modules internes."""

    parsed = parser.parse_email(raw)

    hops: list[HopInfo] = []
    resolved_hops: list[ResolvedIP] = []
    previous_timestamp = None

    for hop in parsed.hops:
        if hop.from_ip:
            resolved = resolver.resolve(hop.from_ip)
            dnsbl = resolver.dnsbl_check(hop.from_ip)
        else:
            resolved = ResolvedIP(ip=hop.from_ip or "", ip_version=0)
            dnsbl = {"spamcop": None, "spamhaus": None}
        resolved_hops.append(resolved)

        delay = None
        if hop.timestamp is not None and previous_timestamp is not None:
            delay = int((hop.timestamp - previous_timestamp).total_seconds())
        if hop.timestamp is not None:
            previous_timestamp = hop.timestamp

        hops.append(
            HopInfo(
                hop_index=hop.index,
                ip=hop.from_ip,
                ip_version=resolved.ip_version,
                ptr=resolved.ptr,
                country=resolved.country,
                country_code=resolved.country_code,
                city=resolved.city,
                org=resolved.org,
                timestamp=hop.timestamp,
                delay_seconds=delay,
                is_private=resolved.is_private,
                dnsbl=dnsbl,
            )
        )

    detection = detect(parsed, resolved=resolved_hops)

    return AnalysisResult(
        hops=hops,
        auth=AuthResult(
            spf=detection.auth.spf,
            dkim=detection.auth.dkim,
            dmarc=detection.auth.dmarc,
            spf_detail=detection.auth.spf_detail,
            dkim_domain=detection.auth.dkim_domain,
        ),
        filter_verdict=FilterVerdict(
            source=parsed.filter_verdict.source,
            is_spam=parsed.filter_verdict.is_spam,
            score=parsed.filter_verdict.score,
            details=parsed.filter_verdict.details,
        ),
        anomalies=[
            AnomalyItem(type=a.type, severity=a.severity, description=a.description)
            for a in detection.anomalies
        ],
        verdict=detection.verdict,
        from_domain=_domain_of(parsed.from_header),
        to_domain=_domain_of(parsed.to_header),
        subject=parsed.subject,
        message_id=parsed.message_id,
        truncated=parsed.truncated,
        raw_size_bytes=parsed.raw_size_bytes,
        analyzed_size_bytes=parsed.analyzed_size_bytes,
        geoip_warning=resolver.geoip_warning,
    )


def _domain_of(address_header: str | None) -> str | None:
    """Extrait le domaine d'un en-tete d'adresse (From, To)."""

    if not address_header:
        return None
    _, email_address = parseaddr(address_header)
    if "@" not in email_address:
        return None
    return email_address.rsplit("@", 1)[1].lower()


# Sert l'interface statique a la racine. Monte en dernier pour que /health et
# /analyze, definis plus haut, restent prioritaires.
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
