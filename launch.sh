#!/usr/bin/env bash
#
# Lanceur du serveur web SpamCap (Uvicorn via uv).
#
# Usage :
#   ./launch.sh            Mode développement (rechargement auto, 127.0.0.1:8000)
#   ./launch.sh dev        Idem
#   ./launch.sh prod       Mode production (0.0.0.0:8000, sans rechargement)
#
# Variables d'environnement surchargeables :
#   HOST   Adresse d'écoute (défaut : 127.0.0.1 en dev, 0.0.0.0 en prod)
#   PORT   Port d'écoute (défaut : 8000)

set -euo pipefail

readonly APP="backend.main:app"
readonly GEOIP_DB="data/GeoLite2-City.mmdb"

MODE="${1:-dev}"

# Se placer à la racine du projet, quel que soit le répertoire d'appel.
cd "$(dirname "$0")"

if ! command -v uv >/dev/null 2>&1; then
    echo "Erreur : uv est introuvable. Installez-le depuis https://astral.sh/uv" >&2
    exit 1
fi

if [ ! -f "$GEOIP_DB" ]; then
    echo "Avertissement : base GeoIP absente ($GEOIP_DB)." >&2
    echo "La géolocalisation sera vide. Voir scripts/download_geoip.sh." >&2
fi

case "$MODE" in
    dev)
        HOST="${HOST:-127.0.0.1}"
        PORT="${PORT:-8000}"
        echo "Démarrage en mode développement sur http://${HOST}:${PORT}"
        exec uv run uvicorn "$APP" --reload --host "$HOST" --port "$PORT"
        ;;
    prod)
        HOST="${HOST:-0.0.0.0}"
        PORT="${PORT:-8000}"
        echo "Synchronisation de l'environnement (uv sync --frozen)..."
        uv sync --frozen
        echo "Démarrage en mode production sur http://${HOST}:${PORT}"
        exec uv run uvicorn "$APP" --host "$HOST" --port "$PORT"
        ;;
    *)
        echo "Erreur : mode inconnu \"$MODE\". Utilisez \"dev\" ou \"prod\"." >&2
        exit 1
        ;;
esac
