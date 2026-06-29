#!/usr/bin/env bash
#
# Lanceur du serveur web SpamCap (Uvicorn via uv).
#
# Usage :
#   ./launch.sh            Mode développement (rechargement auto, 127.0.0.1:8001)
#   ./launch.sh dev        Idem
#   ./launch.sh prod       Mode production (0.0.0.0:8001, sans rechargement)
#
# Au démarrage, le script ouvre la page dans le navigateur par défaut une fois
# le serveur prêt. Si le port demandé est occupé, il bascule automatiquement
# sur le port libre suivant (8001, 8002, ...).
#
# Variables d'environnement surchargeables :
#   HOST       Adresse d'écoute (défaut : 127.0.0.1 en dev, 0.0.0.0 en prod)
#   PORT       Port d'écoute souhaité (défaut : 8001)
#   NO_BROWSER Si défini (à n'importe quelle valeur), n'ouvre pas le navigateur.

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

# Teste si un port TCP est déjà ouvert sur la boucle locale.
port_occupe() {
    (echo >"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1
}

# Renvoie le premier port libre à partir du port demandé (jusqu'à +20).
trouver_port_libre() {
    local demande="$1"
    local port="$demande"
    local maximum=$((demande + 20))
    while [ "$port" -lt "$maximum" ]; do
        if ! port_occupe "$port"; then
            if [ "$port" != "$demande" ]; then
                echo "Port $demande occupé : utilisation du port $port." >&2
            fi
            echo "$port"
            return 0
        fi
        port=$((port + 1))
    done
    echo "$demande"
}

# Démarre le serveur, attend qu'il soit prêt, ouvre le navigateur, puis bloque
# jusqu'à l'arrêt. Le premier argument est "oui" pour activer le rechargement
# automatique (mode dev).
lancer_serveur() {
    local avec_reload="$1"

    PORT="$(trouver_port_libre "$PORT")"

    # Hôte joignable localement pour la sonde et le navigateur : "0.0.0.0"
    # n'est pas une cible de connexion valide, on retombe sur 127.0.0.1.
    local hote_local="$HOST"
    if [ "$HOST" = "0.0.0.0" ] || [ "$HOST" = "::" ]; then
        hote_local="127.0.0.1"
    fi

    echo "Démarrage de SpamCap sur http://${hote_local}:${PORT}"

    # Démarrer le serveur en arrière-plan pour pouvoir sonder le port puis
    # ouvrir le navigateur sans bloquer.
    if [ "$avec_reload" = "oui" ]; then
        uv run uvicorn "$APP" --reload --host "$HOST" --port "$PORT" &
    else
        uv run uvicorn "$APP" --host "$HOST" --port "$PORT" &
    fi
    local server_pid=$!

    # Arrêter proprement le serveur à la sortie (Ctrl+C).
    trap 'kill "$server_pid" 2>/dev/null || true' INT TERM EXIT

    # Attendre que le port soit réellement ouvert avant d'ouvrir le navigateur ;
    # uvicorn n'ouvre le port qu'une fois l'application démarrée. Si le serveur
    # s'arrête avant, c'est un échec de démarrage.
    local pret="non"
    while kill -0 "$server_pid" 2>/dev/null; do
        if port_occupe "$PORT"; then
            pret="oui"
            break
        fi
        sleep 1
    done

    if [ "$pret" != "oui" ]; then
        echo "Le serveur s'est arrêté avant d'être prêt." >&2
        exit 1
    fi

    # Le serveur est prêt : ouvrir le navigateur, sans bloquer.
    if [ -z "${NO_BROWSER:-}" ] && command -v xdg-open >/dev/null 2>&1; then
        xdg-open "http://${hote_local}:${PORT}" >/dev/null 2>&1 || true
    fi

    echo "Appuyez sur Ctrl+C pour arrêter."
    wait "$server_pid"
}

case "$MODE" in
    dev)
        HOST="${HOST:-127.0.0.1}"
        PORT="${PORT:-8001}"
        lancer_serveur "oui"
        ;;
    prod)
        HOST="${HOST:-0.0.0.0}"
        PORT="${PORT:-8001}"
        echo "Synchronisation de l'environnement (uv sync --frozen)..."
        uv sync --frozen
        lancer_serveur "non"
        ;;
    *)
        echo "Erreur : mode inconnu \"$MODE\". Utilisez \"dev\" ou \"prod\"." >&2
        exit 1
        ;;
esac
