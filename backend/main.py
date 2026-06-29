"""Application FastAPI de SpamCap.

Point d'entrée du service. Expose deux routes :

- ``POST /analyze`` : reçoit un en-tête brut, renvoie un
  :class:`AnalysisResult` (parcours résolu, DNSBL, anomalies, verdict).
- ``GET /health`` : sonde de supervision.

L'orchestration de l'analyse vit dans :mod:`backend.analysis` ; ce module se
limite au cadre web : routes, plafonnement, et service du frontend statique.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend import parser
from backend.analysis import build_analysis
from backend.models import AnalysisResult, AnalyzeRequest
from backend.resolver import Resolver

# Origines autorisées pour le frontend en développement local.
ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Plafonnement simple : nombre maximal de requêtes par client sur la fenêtre.
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

# Historique des appels par client, pour le plafonnement en mémoire.
_request_history: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def rate_limit(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Plafonne le nombre de requêtes par client sur une fenêtre glissante."""

    client = request.client.host if request.client else "inconnu"
    now = time.monotonic()
    history = _request_history[client]

    while history and now - history[0] > RATE_LIMIT_WINDOW_SECONDS:
        history.popleft()

    if len(history) >= RATE_LIMIT_REQUESTS:
        return JSONResponse(
            status_code=429,
            content={"detail": "Trop de requêtes. Réessayez dans un instant."},
        )

    history.append(now)
    return await call_next(request)


def get_resolver() -> Iterator[Resolver]:
    """Fournit un résolveur dédié à la requête.

    Une instance par requête garantit que le cache WHOIS n'est jamais partagé
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
    """Analyse un en-tête brut et renvoie le résultat complet."""

    raw = request.raw_headers
    if len(raw.encode("utf-8")) > parser.MAX_INPUT_BYTES:
        raise HTTPException(
            status_code=413,
            detail="En-tête trop volumineux. Seuls les en-têtes sont utiles.",
        )

    return build_analysis(raw, resolver)


# Sert l'interface statique à la racine. Montée en dernier pour que /health et
# /analyze, définis plus haut, restent prioritaires.
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
