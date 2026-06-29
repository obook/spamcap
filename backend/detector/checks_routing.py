"""Vérifications fondées sur le parcours : horodatages, relais, MX."""

from __future__ import annotations

from backend.emailutil import domain_of
from backend.parser import ParsedEmail
from backend.resolver import ResolvedIP, is_private_ip

from .domains import registrable
from .models import (
    MAX_PLAUSIBLE_GAP_SECONDS,
    Anomaly,
    MxResolver,
    SEVERITY_MAJOR,
    SEVERITY_MINOR,
)


def check_timestamps(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale un horodatage en arrière ou un délai inhabituel entre sauts."""

    anomalies: list[Anomaly] = []

    previous = None
    for hop in parsed.hops:
        if hop.timestamp is None:
            continue
        if previous is not None:
            delta = (hop.timestamp - previous).total_seconds()
            if delta < 0:
                anomalies.append(
                    Anomaly(
                        "timestamp_inversion",
                        SEVERITY_MAJOR,
                        "Horodatage incohérent : un saut précède "
                        "le saut antérieur.",
                    )
                )
            elif delta > MAX_PLAUSIBLE_GAP_SECONDS:
                anomalies.append(
                    Anomaly(
                        "timestamp_gap",
                        SEVERITY_MINOR,
                        f"Délai inhabituel entre deux sauts ({int(delta)} s).",
                    )
                )
        previous = hop.timestamp

    return anomalies


def check_private_injection(parsed: ParsedEmail) -> list[Anomaly]:
    """Signale une IP privée placée entre deux relais publics."""

    anomalies: list[Anomaly] = []
    hops = parsed.hops

    for index in range(1, len(hops) - 1):
        current = hops[index].from_ip
        before = hops[index - 1].from_ip
        after = hops[index + 1].from_ip
        if not (current and before and after):
            continue
        inserted = (
            is_private_ip(current)
            and not is_private_ip(before)
            and not is_private_ip(after)
        )
        if inserted:
            anomalies.append(
                Anomaly(
                    "private_ip_injected",
                    SEVERITY_MAJOR,
                    f"IP privée insérée entre deux relais publics "
                    f"({current}).",
                )
            )

    return anomalies


def check_from_relay(
    parsed: ParsedEmail, resolved: list[ResolvedIP] | None
) -> list[Anomaly]:
    """Signale un écart entre le domaine From et le PTR du premier relais."""

    if not resolved:
        return []

    from_domain = domain_of(parsed.from_header)
    first_ptr = resolved[0].ptr if resolved else None
    if not from_domain or not first_ptr:
        return []

    if registrable(first_ptr) != registrable(from_domain):
        return [
            Anomaly(
                "from_relay_mismatch",
                SEVERITY_MINOR,
                f"Le domaine expéditeur ({from_domain}) diffère du premier "
                f"relais ({first_ptr}).",
            )
        ]

    return []


def check_first_hop_mx(
    parsed: ParsedEmail, mx_resolver: MxResolver | None
) -> list[Anomaly]:
    """Signale un premier saut absent des MX publiés du domaine expéditeur."""

    if mx_resolver is None or not parsed.hops:
        return []

    from_domain = domain_of(parsed.from_header)
    first_ip = parsed.hops[0].from_ip
    if not from_domain or not first_ip:
        return []

    mx_ips = mx_resolver(from_domain)
    if not mx_ips:
        # Recherche en échec ou aucun MX : preuves insuffisantes pour signaler.
        return []

    if first_ip not in mx_ips:
        return [
            Anomaly(
                "mx_mismatch",
                SEVERITY_MINOR,
                f"Premier relais ({first_ip}) absent des serveurs MX de "
                f"{from_domain}.",
            )
        ]

    return []
