"""Résolution d'IP : DNS inverse, géolocalisation, organisation, IP privées.

Chaque IP de saut trouvée par l'analyseur est enrichie ici avec :

- son nom DNS inverse (PTR), via dnspython ;
- son pays et sa ville, via la base MaxMind GeoLite2 ;
- son organisation et la description de son ASN, via WHOIS (ipwhois).

Chaque résolution se dégrade proprement : un dépassement de délai réseau ou
un enregistrement absent donne ``None`` (affiché "inconnu" dans l'interface),
jamais une exception. Les adresses privées sont étiquetées localement et
n'effectuent aucune résolution réseau.

Une instance :class:`Resolver` porte un cache de session, de sorte qu'une même
IP n'est jamais interrogée deux fois au cours d'une analyse. Le cache est lié à
l'instance et ne doit pas être partagé entre les requêtes de plusieurs
utilisateurs. Les modèles sans état vivent dans :mod:`backend.resolver.models`.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import dns.resolver
import dns.reversename
import geoip2.database
import geoip2.errors
import requests
from ipwhois import IPWhois
from ipwhois.exceptions import BaseIpwhoisException

from .models import (
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_GEOIP_PATH,
    DNSBL_ZONES,
    ResolvedIP,
    dnsbl_query_name,
    is_private_ip,
)

__all__ = [
    "Resolver",
    "ResolvedIP",
    "is_private_ip",
    "dnsbl_query_name",
    "DNSBL_ZONES",
    "DEFAULT_GEOIP_PATH",
    "DEFAULT_DNS_TIMEOUT",
]


class Resolver:
    """Résout les métadonnées d'IP, avec dégradation propre et cache."""

    def __init__(
        self,
        geoip_path: Path | None = DEFAULT_GEOIP_PATH,
        dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    ) -> None:
        self.dns_timeout = dns_timeout
        self.geoip_warning: str | None = None
        self._whois_cache: dict[str, str | None] = {}
        self._domain_cache: dict[
            str, tuple[str | None, str | None, str | None]
        ] = {}
        self._geoip_reader = self._open_geoip(geoip_path)

        self._dns = dns.resolver.Resolver()
        self._dns.lifetime = dns_timeout
        self._dns.timeout = dns_timeout

    @property
    def geoip_available(self) -> bool:
        return self._geoip_reader is not None

    def resolve(self, ip: str) -> ResolvedIP:
        """Résout une IP unique, sans jamais lever d'exception."""

        try:
            version = ipaddress.ip_address(ip).version
        except ValueError:
            return ResolvedIP(ip=ip, ip_version=0)

        if is_private_ip(ip):
            # Une adresse privée n'a ni PTR public, ni géolocalisation, ni
            # propriétaire WHOIS.
            return ResolvedIP(ip=ip, ip_version=version, is_private=True)

        country, country_code, city = self._lookup_geo(ip)
        ptr, has_reverse = self._lookup_ptr(ip)
        return ResolvedIP(
            ip=ip,
            ip_version=version,
            ptr=ptr,
            has_reverse=has_reverse,
            country=country,
            country_code=country_code,
            city=city,
            org=self._org(ip),
            is_private=False,
        )

    def close(self) -> None:
        """Libère le lecteur GeoIP. Appelable plusieurs fois sans risque."""

        if self._geoip_reader is not None:
            self._geoip_reader.close()
            self._geoip_reader = None

    def _open_geoip(
        self, geoip_path: Path | None
    ) -> geoip2.database.Reader | None:
        if geoip_path is None:
            self.geoip_warning = (
                "Géolocalisation désactivée : aucune base configurée."
            )
            return None
        # Un chemin relatif est ancré à la racine du projet, pour fonctionner
        # quel que soit le répertoire de lancement.
        path = Path(geoip_path)
        if not path.is_absolute():
            path = Path(__file__).resolve().parent.parent.parent / path
        try:
            return geoip2.database.Reader(str(path))
        except (FileNotFoundError, OSError):
            self.geoip_warning = (
                f"Base GeoLite2 introuvable à {geoip_path} ; "
                "le pays et la ville seront vides."
            )
            return None

    def _lookup_ptr(self, ip: str) -> tuple[str | None, bool | None]:
        """Renvoie le couple (nom PTR, has_reverse).

        ``has_reverse`` vaut True si un PTR existe, False si son absence est
        confirmée (NXDOMAIN ou aucun enregistrement), et None si la résolution
        a échoué (délai, erreur réseau).
        """

        try:
            reverse_name = dns.reversename.from_address(ip)
            answer = self._dns.resolve(reverse_name, "PTR")
            return str(answer[0]).rstrip("."), True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None, False
        except Exception:
            return None, None

    def forward_lookup(self, host: str) -> str | None:
        """Résout un nom d'hôte en IP (A puis AAAA), ou None.

        Sert à géolocaliser un saut qui n'a pas d'IP mais porte un nom d'hôte.
        L'IP renvoyée est l'adresse actuelle du nom, pas forcément celle du
        transit d'origine : l'appelant doit le signaler.
        """

        for record_type in ("A", "AAAA"):
            try:
                answer = self._dns.resolve(host, record_type)
            except Exception:
                continue
            if answer:
                return str(answer[0])
        return None

    def _lookup_geo(
        self, ip: str
    ) -> tuple[str | None, str | None, str | None]:
        if self._geoip_reader is None:
            return None, None, None
        try:
            record = self._geoip_reader.city(ip)
            return (
                record.country.name,
                record.country.iso_code,
                record.city.name,
            )
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
        # Repli sur le nom du réseau RDAP (par exemple "MSFT") quand la
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
            # Délai, SERVFAIL, famille non prise en charge : inconnu, jamais
            # une erreur.
            return None

    def domain_dates(
        self, domain: str
    ) -> tuple[str | None, str | None, str | None]:
        """Renvoie (création, mise à jour, bureau d'enregistrement) via RDAP.

        Un domaine récemment créé est un indice d'hameçonnage ; le bureau
        d'enregistrement (registrar) renseigne sur la provenance du domaine.
        Renvoie (None, None, None) en cas d'échec ou de TLD sans RDAP. Le
        résultat est mis en cache par instance.
        """

        if not domain:
            return None, None, None
        if domain in self._domain_cache:
            return self._domain_cache[domain]
        info = self._lookup_domain_dates(domain)
        self._domain_cache[domain] = info
        return info

    def _lookup_domain_dates(
        self, domain: str
    ) -> tuple[str | None, str | None, str | None]:
        try:
            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/rdap+json"},
                timeout=self.dns_timeout,
            )
        except requests.RequestException:
            return None, None, None
        if response.status_code != 200:
            return None, None, None
        try:
            payload = response.json()
        except ValueError:
            return None, None, None

        created = None
        updated = None
        for event in payload.get("events", []):
            action = event.get("eventAction")
            if action == "registration":
                created = event.get("eventDate")
            elif action == "last changed":
                updated = event.get("eventDate")
        registrar = self._extract_registrar(payload.get("entities", []))
        return created, updated, registrar

    @staticmethod
    def _extract_registrar(entities: list) -> str | None:
        """Extrait le nom du bureau d'enregistrement des entités RDAP.

        L'entité de rôle "registrar" porte son nom dans son vCard (champ
        "fn"). Renvoie None si aucune entité de ce rôle n'expose de nom.
        """

        for entity in entities:
            if "registrar" not in entity.get("roles", []):
                continue
            vcard = entity.get("vcardArray")
            if not isinstance(vcard, list) or len(vcard) < 2:
                continue
            for field in vcard[1]:
                if (
                    isinstance(field, list)
                    and len(field) >= 4
                    and field[0] == "fn"
                    and field[3]
                ):
                    return str(field[3])
        return None
