"""Modèles et fonctions sans état de la résolution d'IP."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

import dns.reversename

# Chemin de la base GeoLite2 City. Surchargeable par la variable
# d'environnement SPAMCAP_GEOIP ; sinon, data/GeoLite2-City.mmdb relatif à la
# racine du dépôt.
DEFAULT_GEOIP_PATH = Path(
    os.environ.get("SPAMCAP_GEOIP", "data/GeoLite2-City.mmdb")
)

# Délai en secondes avant d'abandonner une requête DNS et de la dire inconnue.
DEFAULT_DNS_TIMEOUT = 3.0

# Zones de listes noires DNS interrogées pour chaque IP publique. La clé est le
# nom court utilisé dans le résultat et dans le badge de l'interface.
DNSBL_ZONES = {
    "spamcop": "bl.spamcop.net",
    "spamhaus": "zen.spamhaus.org",
}


def dnsbl_query_name(ip: str, zone: str) -> str:
    """Construit le nom de requête DNSBL d'une IP, octets ou nibbles inversés.

    Réutilise la machinerie du pointeur inverse : ``1.2.3.4`` devient
    ``4.3.2.1.bl.spamcop.net`` et une adresse IPv6 devient sa séquence de
    nibbles inversée suivie de la zone.
    """

    reverse = dns.reversename.from_address(ip).to_text().rstrip(".")
    reverse = reverse.removesuffix(".in-addr.arpa").removesuffix(".ip6.arpa")
    return f"{reverse}.{zone}"


@dataclass
class ResolvedIP:
    """Vue enrichie d'une adresse IP unique."""

    ip: str
    ip_version: int
    ptr: str | None = None
    has_reverse: bool | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    org: str | None = None
    is_private: bool = False


def is_private_ip(ip: str) -> bool:
    """Renvoie True pour les adresses privées, loopback ou link-local."""

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local
