#!/usr/bin/env bash
#
# Telecharge la base MaxMind GeoLite2 City dans data/GeoLite2-City.mmdb.
#
# Prerequis : un compte MaxMind gratuit et une cle de licence
# (https://www.maxmind.com/en/geolite2/signup). Fournir la cle par la variable
# d'environnement MAXMIND_LICENSE_KEY, jamais en clair dans un fichier versionne.
#
# Usage :
#   MAXMIND_LICENSE_KEY="votre_cle" scripts/download_geoip.sh

set -euo pipefail

readonly EDITION="GeoLite2-City"
readonly TARGET_DIR="data"
readonly TARGET="${TARGET_DIR}/${EDITION}.mmdb"

# Se placer a la racine du projet, quel que soit le repertoire d'appel.
cd "$(dirname "$0")/.."

if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    echo "Erreur : variable MAXMIND_LICENSE_KEY absente." >&2
    echo "Generez une cle sur https://www.maxmind.com/en/accounts puis :" >&2
    echo "  MAXMIND_LICENSE_KEY=\"votre_cle\" scripts/download_geoip.sh" >&2
    exit 1
fi

mkdir -p "$TARGET_DIR"

url="https://download.maxmind.com/app/geoip_download"
url="${url}?edition_id=${EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo "Telechargement de ${EDITION}..."
if ! curl -fsSL "$url" -o "${workdir}/${EDITION}.tar.gz"; then
    echo "Erreur : telechargement echoue. Verifiez la cle de licence." >&2
    exit 1
fi

echo "Extraction..."
tar -xzf "${workdir}/${EDITION}.tar.gz" -C "$workdir"

# L'archive contient un dossier date (GeoLite2-City_AAAAMMJJ) avec le .mmdb.
mmdb="$(find "$workdir" -name "${EDITION}.mmdb" -print -quit)"
if [ -z "$mmdb" ]; then
    echo "Erreur : ${EDITION}.mmdb introuvable dans l'archive." >&2
    exit 1
fi

mv "$mmdb" "$TARGET"
echo "Base installee : ${TARGET}"
