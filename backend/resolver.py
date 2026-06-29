"""Résolution d'IP : DNS inverse, géolocalisation, organisation, IP privées.

Chaque IP de saut trouvée par l'analyseur est enrichie ici avec :

- son nom DNS inverse (PTR), via dnspython ;
- son pays et sa ville, via la base MaxMind GeoLite2 ;
- son organisation et la description de son ASN, via WHOIS (ipwhois).

Chaque résolution se dégrade proprement : un dépassement de délai réseau ou un
enregistrement absent donne ``None`` (affiché "inconnu" dans l'interface),
jamais une exception. Les adresses privées sont étiquetées localement et
n'effectuent aucune résolution réseau.

Une instance :class:`Resolver` porte un cache WHOIS de session, de sorte qu'une
même IP n'est jamais interrogée deux fois au cours d'une analyse. Le cache est
volontairement lié à l'instance et ne doit pas être partagé entre les requêtes
de plusieurs utilisateurs.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

import dns.resolver
import dns.reversename
import geoip2.database
import geoip2.errors
from ipwhois import IPWhois
from ipwhois.exceptions import BaseIpwhoisException

# Chemin de la base GeoLite2 City. Surchargeable par la variable d'environnement
# SPAMCAP_GEOIP ; sinon, data/GeoLite2-City.mmdb relatif a la racine du depot.
DEFAULT_GEOIP_PATH = Path(os.environ.get("SPAMCAP_GEOIP", "data/GeoLite2-City.mmdb"))

# Délai en secondes avant qu'une requête DNS soit abandonnée et signalée inconnue.
DEFAULT_DNS_TIMEOUT = 3.0

# Zones de listes noires DNS interrogées pour chaque IP publique. La clé est le
# nom court utilisé dans le dictionnaire de résultat et dans le badge de l'interface.
DNSBL_ZONES = {
    "spamcop": "bl.spamcop.net",
    "spamhaus": "zen.spamhaus.org",
}


def dnsbl_query_name(ip: str, zone: str) -> str:
    """Construit le nom de requête DNSBL d'une IP, octets IPv4 ou nibbles IPv6 inversés.

    Réutilise la machinerie du pointeur inverse : ``1.2.3.4`` devient
    ``4.3.2.1.bl.spamcop.net`` et une adresse IPv6 devient sa séquence de nibbles
    inversée suivie de la zone.
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
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    org: str | None = None
    is_private: bool = False


def is_private_ip(ip: str) -> bool:
    """Renvoie True pour les adresses privées, loopback ou link-local (v4 et v6)."""

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


class Resolver:
    """Résout les métadonnées d'IP avec dégradation propre et cache par instance."""

    def __init__(
        self,
        geoip_path: Path | None = DEFAULT_GEOIP_PATH,
        dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    ) -> None:
        self.dns_timeout = dns_timeout
        self.geoip_warning: str | None = None
        self._whois_cache: dict[str, str | None] = {}
        self._geoip_reader = self._open_geoip(geoip_path)

        self._dns = dns.resolver.Resolver()
        self._dns.lifetime = dns_timeout
        self._dns.timeout = dns_timeout

    @property
    def geoip_available(self) -> bool:
        return self._geoip_reader is not None

    def resolve(self, ip: str) -> ResolvedIP:
        """Résout une IP unique en un :class:`ResolvedIP`, sans jamais lever d'exception."""

        try:
            version = ipaddress.ip_address(ip).version
        except ValueError:
            return ResolvedIP(ip=ip, ip_version=0)

        if is_private_ip(ip):
            # Une adresse privée n'a ni PTR public, ni géolocalisation, ni
            # propriétaire WHOIS.
            return ResolvedIP(ip=ip, ip_version=version, is_private=True)

        country, country_code, city = self._lookup_geo(ip)
        return ResolvedIP(
            ip=ip,
            ip_version=version,
            ptr=self._lookup_ptr(ip),
            country=country,
            country_code=country_code,
            city=city,
            org=self._org(ip),
            is_private=False,
        )

    def close(self) -> None:
        """Libère le lecteur GeoIP. Peut être appelé plusieurs fois sans risque."""

        if self._geoip_reader is not None:
            self._geoip_reader.close()
            self._geoip_reader = None

    def _open_geoip(
        self, geoip_path: Path | None
    ) -> geoip2.database.Reader | None:
        if geoip_path is None:
            self.geoip_warning = "Géolocalisation désactivée : aucune base configurée."
            return None
        # Un chemin relatif est ancré à la racine du projet, pour fonctionner
        # quel que soit le répertoire de lancement.
        path = Path(geoip_path)
        if not path.is_absolute():
            path = Path(__file__).resolve().parent.parent / path
        try:
            return geoip2.database.Reader(str(path))
        except (FileNotFoundError, OSError):
            self.geoip_warning = (
                f"Base GeoLite2 introuvable à {geoip_path} ; "
                "le pays et la ville seront vides."
            )
            return None

    def _lookup_ptr(self, ip: str) -> str | None:
        try:
            reverse_name = dns.reversename.from_address(ip)
            answer = self._dns.resolve(reverse_name, "PTR")
            return str(answer[0]).rstrip(".")
        except Exception:
            # Tout échec DNS (délai, NXDOMAIN, absence de PTR) signifie "inconnu".
            return None

    def _lookup_geo(
        self, ip: str
    ) -> tuple[str | None, str | None, str | None]:
        if self._geoip_reader is None:
            return None, None, None
        try:
            record = self._geoip_reader.city(ip)
            return record.country.name, record.country.iso_code, record.city.name
        except geoip2.errors.AddressNotFoundError:
            return None, None, None
        except (ValueError, geoip2.errors.GeoIP2Error):
            return None, None, None

    def _org(self, ip: str) -> str | None:
        if ip in self._whois_cache:
            return self._whois_cache[ip]
        org = self._lookup_org(ip)
        self._whois_cache[ip] = org
        return org

    def _lookup_org(self, ip: str) -> str | None:
        try:
            result = IPWhois(ip).lookup_rdap(depth=0)
        except (BaseIpwhoisException, ValueError, OSError):
            return None
        description = result.get("asn_description")
        asn = result.get("asn")
        # Les services RDAP renvoient parfois "NA" quand l'information manque.
        if description in (None, "", "NA"):
            description = None
        if asn in (None, "", "NA"):
            asn = None
        # Repli sur le nom du reseau RDAP (par exemple "MSFT") quand la
        # description d'ASN manque, ce qui arrive souvent en IPv6.
        if description is None:
            network_name = (result.get("network") or {}).get("name")
            if network_name and network_name != "NA":
                description = network_name
        if description and asn:
            return f"{description} (AS{asn})"
        return description

    def dnsbl_check(self, ip: str) -> dict[str, bool | None]:
        """Vérifie une IP face aux listes noires DNS configurées.

        Renvoie une entrée par zone : ``True`` si listée, ``False`` sinon, et
        ``None`` quand la réponse est inconnue (délai dépassé, ou zone qui ne
        prend pas en charge la famille d'adresses). Les adresses privées sont
        renvoyées comme inconnues.
        """

        result: dict[str, bool | None] = {key: None for key in DNSBL_ZONES}
        if is_private_ip(ip):
            return result

        for key, zone in DNSBL_ZONES.items():
            result[key] = self._dnsbl_query(ip, zone)
        return result

    def _dnsbl_query(self, ip: str, zone: str) -> bool | None:
        try:
            query = dnsbl_query_name(ip, zone)
        except ValueError:
            return None
        try:
            answers = self._dns.resolve(query, "A")
            # Une IP listée répond dans la plage 127.0.0.0/8.
            return any(str(record).startswith("127.") for record in answers)
        except dns.resolver.NXDOMAIN:
            return False
        except Exception:
            # Délai, SERVFAIL, famille non prise en charge : inconnu, jamais une erreur.
            return None
