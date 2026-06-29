"""Tests unitaires de backend.detector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.detector import (
    SEVERITY_MAJOR,
    SEVERITY_MINOR,
    VERDICT_DOUBTFUL,
    VERDICT_LEGITIMATE,
    VERDICT_SUSPECT,
    detect,
    parse_auth,
)
from backend.parser import ParsedEmail, RawHop
from backend.resolver import ResolvedIP

BASE_TIME = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


def hop(index: int, ip: str | None, offset_seconds: int = 0) -> RawHop:
    return RawHop(
        index=index,
        from_ip=ip,
        by_ip=None,
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        raw="",
    )


def types_of(result) -> set[str]:
    return {anomaly.type for anomaly in result.anomalies}


def test_parse_auth_reads_all_results() -> None:
    parsed = ParsedEmail(
        authentication_results=(
            "mx.recipient.com; spf=pass smtp.mailfrom=sender.com; "
            "dkim=pass header.d=sender.com; dmarc=pass"
        ),
        received_spf="pass (sender.com: designates 8.8.8.8 as permitted sender)",
    )
    auth = parse_auth(parsed)

    assert auth.spf == "pass"
    assert auth.dkim == "pass"
    assert auth.dmarc == "pass"
    assert auth.dkim_domain == "sender.com"
    assert auth.spf_detail is not None


def test_spf_fail_is_major_and_doubtful() -> None:
    parsed = ParsedEmail(authentication_results="x; spf=fail; dkim=pass; dmarc=fail")
    result = detect(parsed)

    assert result.verdict == VERDICT_DOUBTFUL
    assert "spf_fail" in types_of(result)
    assert "dmarc_fail" in types_of(result)


def test_spf_softfail_is_minor_and_suspect() -> None:
    parsed = ParsedEmail(authentication_results="x; spf=softfail; dkim=pass; dmarc=pass")
    result = detect(parsed)

    assert result.verdict == VERDICT_SUSPECT
    anomaly = next(a for a in result.anomalies if a.type == "spf_softfail")
    assert anomaly.severity == SEVERITY_MINOR


def test_timestamp_inversion_is_major() -> None:
    parsed = ParsedEmail(hops=[hop(0, "8.8.8.8", 0), hop(1, "1.1.1.1", -120)])
    result = detect(parsed)

    assert "timestamp_inversion" in types_of(result)
    assert result.verdict == VERDICT_DOUBTFUL


def test_timestamp_gap_is_minor() -> None:
    parsed = ParsedEmail(hops=[hop(0, "8.8.8.8", 0), hop(1, "1.1.1.1", 7200)])
    result = detect(parsed)

    assert "timestamp_gap" in types_of(result)
    assert result.verdict == VERDICT_SUSPECT


def test_private_ip_between_public_relays_is_major() -> None:
    parsed = ParsedEmail(
        hops=[
            hop(0, "8.8.8.8", 0),
            hop(1, "192.168.1.5", 1),
            hop(2, "1.1.1.1", 2),
        ]
    )
    result = detect(parsed)

    assert "private_ip_injected" in types_of(result)
    assert result.verdict == VERDICT_DOUBTFUL


def test_clean_message_is_legitimate() -> None:
    parsed = ParsedEmail(
        hops=[hop(0, "8.8.8.8", 0), hop(1, "1.1.1.1", 5)],
        authentication_results="x; spf=pass; dkim=pass; dmarc=pass",
    )
    result = detect(parsed)

    assert result.anomalies == []
    assert result.verdict == VERDICT_LEGITIMATE


def test_from_relay_mismatch_when_ptr_differs() -> None:
    parsed = ParsedEmail(hops=[hop(0, "8.8.8.8", 0)], from_header="Bob <bob@good.com>")
    resolved = [ResolvedIP(ip="8.8.8.8", ip_version=4, ptr="mail.evil.com")]

    result = detect(parsed, resolved=resolved)

    assert "from_relay_mismatch" in types_of(result)


def test_from_relay_match_when_same_domain() -> None:
    parsed = ParsedEmail(hops=[hop(0, "8.8.8.8", 0)], from_header="Bob <bob@good.com>")
    resolved = [ResolvedIP(ip="8.8.8.8", ip_version=4, ptr="mx1.good.com")]

    result = detect(parsed, resolved=resolved)

    assert "from_relay_mismatch" not in types_of(result)


def test_mx_check_flags_unlisted_first_hop() -> None:
    parsed = ParsedEmail(hops=[hop(0, "8.8.8.8", 0)], from_header="a@good.com")

    result = detect(parsed, mx_resolver=lambda domain: {"203.0.113.9"})

    anomaly = next(a for a in result.anomalies if a.type == "mx_mismatch")
    assert anomaly.severity == SEVERITY_MINOR


def test_mx_check_passes_when_first_hop_is_mx() -> None:
    parsed = ParsedEmail(hops=[hop(0, "8.8.8.8", 0)], from_header="a@good.com")

    result = detect(parsed, mx_resolver=lambda domain: {"8.8.8.8"})

    assert "mx_mismatch" not in types_of(result)
