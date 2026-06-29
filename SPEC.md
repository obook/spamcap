# SpamCap - Spécification fonctionnelle

Ce document décrit ce que SpamCap analyse, comment il rend son verdict, d'où
viennent les données, et les limites connues. Il complète le `README.md`, qui
couvre l'installation et le lancement.

## Principe

L'utilisateur colle l'en-tête brut d'un courriel. Le service en extrait le
parcours (la suite des serveurs traversés), enrichit chaque saut, recherche les
incohérences de falsification, puis rend un verdict. Aucun courriel n'est
conservé : tout le traitement vit en mémoire le temps de la requête.

Le flux interne, en quatre étapes :

1. `parser` sépare en-têtes et corps, puis extrait la chaîne `Received:` et les
   en-têtes d'authentification et d'information.
2. `resolver` enrichit chaque IP (DNS inverse, géolocalisation, organisation) et
   vérifie sa réputation sur les listes noires DNS.
3. `detector` analyse l'authentification et recherche les anomalies.
4. `main` assemble le tout en un résultat JSON.

## Troncature de l'entrée

Un courriel complet peut peser plusieurs mégaoctets, alors que seuls les
en-têtes comptent. La toute première opération du `parser` est donc :

- Séparation en-têtes / corps sur la première ligne vide (RFC 5322).
- Conservation intégrale du bloc d'en-têtes.
- Du corps, seuls les 500 premiers caractères sont gardés pour un aperçu, jamais
  transmis au backend.
- Toute entrée au-delà de 200 Ko est rejetée par l'API avec un code HTTP 413.

## Champs analysés

### Par saut (`HopInfo`)

| Champ | Source | Description |
|---|---|---|
| `hop_index` | parser | Rang du saut, 0 = serveur d'origine. |
| `ip` | parser | IP source (clause `from`) du champ `Received:`. |
| `from_host` | parser | Nom d'hote du serveur source, utile quand l'IP manque. |
| `ip_version` | resolver | 4 ou 6 ; 0 si l'adresse est invalide. |
| `ptr` | resolver | Nom DNS inverse (PTR). |
| `has_reverse` | resolver | True si un PTR existe, False si son absence est confirmée, None si la résolution a échoué. |
| `country`, `country_code`, `city` | resolver | Géolocalisation MaxMind. |
| `org` | resolver | Organisation et ASN via WHOIS. |
| `timestamp` | parser | Horodatage du champ `Received:`. |
| `delay_seconds` | main | Écart avec le saut précédent. |
| `is_private` | resolver | Vrai pour une adresse privée, loopback ou lien-local. |
| `dnsbl` | resolver | Réputation sur SpamCop SCBL et Spamhaus ZEN. |

Important : dans un courriel brut, les champs `Received:` sont dans l'ordre
inverse (le plus récent en haut). Le parser les inverse pour présenter le
parcours de l'expéditeur vers le destinataire.

### Authentification (`AuthResult`)

`spf`, `dkim`, `dmarc` (résultats `pass` / `fail` / `softfail` / `neutral` /
`none`), plus le détail SPF et le domaine signataire DKIM. Extraits de
`Authentication-Results:`, avec repli sur `Received-SPF:` et `DKIM-Signature:`.

## Critères de détection de falsification

Chaque anomalie porte une sévérité (`minor` ou `major`).

| Anomalie | Sévérité | Déclencheur |
|---|---|---|
| `spf_fail` | majeure | SPF en échec : l'expéditeur n'est pas autorisé. |
| `spf_softfail` | mineure | SPF softfail ou neutral. |
| `dkim_fail` | majeure | Signature DKIM invalide. |
| `dmarc_fail` | majeure | DMARC en échec. |
| `timestamp_inversion` | majeure | Un saut précède le saut antérieur. |
| `timestamp_gap` | mineure | Écart supérieur à une heure entre deux sauts. |
| `private_ip_injected` | majeure | IP privée insérée entre deux relais publics. |
| `from_relay_mismatch` | mineure | Domaine `From:` différent du PTR du premier relais. |
| `mx_mismatch` | mineure | Premier relais absent des MX du domaine expéditeur. |
| `display_name_spoof` | majeure | Le nom affiché évoque un domaine autre que l'adresse réelle. |
| `punycode_domain` | mineure | Domaine expéditeur internationalisé (punycode), vecteur d'homographe. |
| `dmarc_misalignment` | mineure | DKIM valide pour un domaine autre que l'expéditeur, sans DMARC pour le contrôler. |
| `replyto_mismatch` | mineure | Adresse de réponse sur un autre domaine que l'expéditeur. |
| `recent_domain` | mineure | Domaine expéditeur créé il y a moins de 30 jours (RDAP). |

La vérification MX (`mx_mismatch`) est désactivée par défaut dans l'API : elle
génère beaucoup de faux positifs, car les serveurs sortants diffèrent souvent
des serveurs MX entrants. Elle peut être activée en fournissant un résolveur MX
à la fonction `detect`.

### Verdict

- `LÉGITIME` : aucune anomalie.
- `SUSPECT` : uniquement des anomalies mineures.
- `DOUTEUX` : au moins une anomalie majeure.

## Géolocalisation (GeoIP)

La géolocalisation repose sur la base MaxMind GeoLite2 City (format `.mmdb`),
non versionnée. Le chemin par défaut est `data/GeoLite2-City.mmdb`,
surchargeable par la variable d'environnement `SPAMCAP_GEOIP`.

- Sans base, l'application démarre quand même et renvoie des champs
  géographiques vides, avec un avertissement dans la réponse JSON.
- Le script `scripts/download_geoip.sh` télécharge la base de production
  (compte MaxMind gratuit et clé de licence requis).
- Une base de test (`GeoIP2-City-Test.mmdb`) ne couvre qu'un petit jeu d'IP
  précis et ne convient qu'à la démonstration.

## Listes noires DNS (DNSBL)

Pour chaque IP publique, le `resolver` interroge deux zones :

- `bl.spamcop.net` (SpamCop SCBL, par Cisco) ;
- `zen.spamhaus.org` (Spamhaus ZEN, combine SBL, XBL et PBL).

Mécanisme : l'adresse est inversée (octets pour l'IPv4, nibbles pour l'IPv6),
puis le suffixe de la zone est ajouté. Une réponse `127.0.0.x` signifie que l'IP
est listée. Résultat par zone : `True` (listée), `False` (non listée) ou `None`
(inconnu : délai dépassé, ou famille d'adresses non prise en charge). Le support
IPv6 de `bl.spamcop.net` est limité ; le cas échéant, le résultat est `None`.

## Données d'organisation (WHOIS)

L'organisation et l'ASN proviennent de `ipwhois` (requête RDAP). Les résultats
sont mis en cache par instance de `Resolver`, de sorte qu'une même IP n'est
jamais interrogée deux fois au cours d'une analyse. Ce cache n'est pas partagé
entre les requêtes de plusieurs utilisateurs. Quand l'information manque (valeur
`NA` côté service), le champ est renvoyé comme inconnu.

## Verdict du filtre de réception

Beaucoup de courriels portent le verdict du filtre anti-spam qui les a traités.
Pour un message interne (par exemple entre deux boites du même domaine
Microsoft 365), c'est même la seule source de verdict, car SPF, DKIM et DMARC
n'y figurent pas.

SpamCap normalise ces en-têtes propriétaires en une vue commune `FilterVerdict`
(`source`, `is_spam`, `score`, `details`). Deux fournisseurs sont reconnus, et
la liste s'étend en ajoutant une fonction de détection :

- **Microsoft 365 / Exchange** : `X-MS-Exchange-Organization-SCL` (Spam
  Confidence Level), `X-Microsoft-Antispam` (BCL, Bulk Complaint Level),
  `X-Forefront-Antispam-Report` (SFV), `X-MS-Exchange-Organization-AuthAs`. Le
  courriel est considéré indésirable quand SCL est supérieur ou égal à 5, ou
  quand SFV vaut `SPM`.
- **SpamAssassin** : `X-Spam-Flag`, `X-Spam-Status`, `X-Spam-Score`. Le courriel
  est indésirable quand `X-Spam-Flag` vaut `YES` (ou que le statut commence par
  `Yes`).
- **Proxad / Free** : `X-ProXaD-SC` (format `state=HAM|SPAM:catégorie score=N`).
  Le courriel est indésirable quand l'état vaut `SPAM`.

Quand le filtre classe le message comme indésirable, une anomalie mineure
`filter_spam` est levée, ce qui place le verdict au minimum en `SUSPECT`.

## Courriel de masse et expéditeur d'enveloppe

Les en-têtes `List-Id` et `List-Unsubscribe` signalent une infolettre ou une
liste de diffusion ; la plateforme d'envoi (ESP) est lue dans `X-Mailer` ou dans
le suffixe de `Feedback-ID`. La carte affiche alors le type "courriel de masse",
l'ESP et le lien de désabonnement. Sur un courriel de masse, l'anomalie
`replyto_mismatch` est ignorée : une infolettre utilise légitimement une adresse
de réponse d'un autre domaine.

L'en-tête `Return-Path` (expéditeur d'enveloppe, adresse de rebond) est aussi
extrait et affiché dans la carte.

## Portée du verdict et hameçonnage

SpamCap analyse l'acheminement, pas le contenu. Un courriel d'hameçonnage peut
être techniquement authentifié (SPF, DKIM et DMARC qui passent pour un domaine
d'attaquant correctement configuré), tandis que le piège réel se trouve dans le
corps, que SpamCap ne lit pas.

La carte affiche aussi la date de création et de mise à jour du domaine
expéditeur, obtenues par RDAP (`rdap.org`) et mises en cache par requête : un
domaine créé très récemment est un indice classique d'hameçonnage.

Si le courriel porte un en-tête `X-Originating-IP` (ou `X-Sender-IP`,
`X-Source-IP`, `X-Client-IP`), souvent présent sur un envoi par webmail ou par
script, SpamCap affiche l'IP du poste expéditeur : géolocalisée si elle est
publique, étiquetée réseau intranet si elle est privée.

Le verdict n'affirme donc jamais qu'un courriel est sûr. L'interface affiche un
avertissement permanent sous le verdict : SpamCap vérifie l'acheminement, pas le
contenu. Les détecteurs `display_name_spoof`, `punycode_domain`,
`dmarc_misalignment` et `replyto_mismatch` capturent les indices d'usurpation
lisibles dans les en-têtes, sans jamais ouvrir le corps. Un hameçonnage dont la
charge est entièrement dans les liens du corps reste hors de portée d'une analyse
d'en-têtes.

## Vie privée et journalisation

- Aucun courriel n'est conservé : traitement sans état, tout en mémoire.
- Le corps du courriel n'est jamais transmis au backend ni journalisé.
- L'interface construit le DOM par `createElement` et `textContent` : aucune
  donnée réseau n'est injectée en HTML.

## Déploiement

En production, Uvicorn derrière Nginx en proxy inverse.

```nginx
server {
    listen 443 ssl;
    server_name spamcap.exemple.fr;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Lancement du service :

```bash
SPAMCAP_GEOIP=data/GeoLite2-City.mmdb ./launch.sh prod
```

CORS : les origines autorisées sont définies dans `backend/main.py`
(`ALLOWED_ORIGINS`). Pour une mise en production, remplacer les origines locales
par le domaine réel du frontend. Le service applique aussi un plafonnement
simple par client (60 requêtes par minute).
