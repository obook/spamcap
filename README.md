# SpamCap

Analyseur d'en-têtes de courriel avec visualisation du parcours et détection de
falsification.

Collez l'en-tête brut d'un courriel reçu et SpamCap reconstitue son parcours,
serveur par serveur, puis signale les usurpations et les échecs
d'authentification.

## Fonctionnalités

- Liste ordonnée des sauts, de l'expéditeur au destinataire, reconstruite à
  partir des champs `Received:`.
- Par saut : adresse IPv4/IPv6, DNS inverse (PTR), pays, organisation (ASN),
  horodatage et délai entre sauts.
- Vérification de réputation de chaque IP sur les listes noires DNS
  (SpamCop SCBL, Spamhaus ZEN).
- Détection de falsification : résultats SPF, DKIM et DMARC, cohérence des
  horodatages, IP privées insérées entre des relais publics, écart entre
  l'expéditeur et son MX.
- Verdict de légitimité : LÉGITIME, SUSPECT ou DOUTEUX.
- Visualisation en timeline verticale du parcours.
- Raccourci pour signaler le message sur SpamCop.

Aucun courriel n'est conservé. Le traitement est sans état et s'exécute
entièrement en mémoire.

## Prérequis

- [uv](https://astral.sh/uv) pour la gestion de Python et des dépendances.
- Python 3.12 (installé automatiquement par uv depuis `.python-version`).
- Une base MaxMind GeoLite2 City pour la géolocalisation (optionnelle :
  l'application démarre sans elle et renvoie des champs géographiques vides).
  Voir la section GeoIP plus bas.

## Installation

```bash
git clone https://github.com/obook/spamcap.git
cd spamcap
uv sync
```

`uv sync` crée l'environnement virtuel et installe chaque dépendance depuis
`uv.lock`, garantissant une installation reproductible.

## Lancement

Le script `launch.sh` enveloppe le serveur dans les deux modes :

```bash
./launch.sh          # développement, rechargement auto, 127.0.0.1:8000
./launch.sh prod     # production, 0.0.0.0:8000
```

`HOST` et `PORT` surchargent les valeurs par défaut, par exemple
`PORT=9000 ./launch.sh`.

Les commandes directes équivalentes sont :

```bash
uv run uvicorn backend.main:app --reload
uv run uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

L'application est alors accessible sur http://127.0.0.1:8000.

En production, derrière Nginx en proxy inverse devant Uvicorn. Les détails de
déploiement sont documentés dans `SPEC.md`.

## Base GeoIP

La géolocalisation repose sur la base MaxMind GeoLite2 City, qui n'est pas
fournie avec le dépôt. Téléchargez `GeoLite2-City.mmdb` dans `data/` à l'aide
d'un compte MaxMind gratuit et d'une clé de licence. Un script d'aide est fourni :

```bash
scripts/download_geoip.sh
```

Sans ce fichier, SpamCap fonctionne quand même et renvoie `null` pour le pays et
la ville.

## Organisation du projet

```
backend/    Service FastAPI : analyse, résolution, détection, modèles
frontend/   Interface monopage (HTML, CSS, JavaScript vanilla)
data/        Base GeoLite2 (non versionnée)
SPEC.md      Spécification fonctionnelle et critères de détection
```

## Licence

À définir.
