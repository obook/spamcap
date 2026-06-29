"""Tests unitaires des détecteurs d'usurpation fondés sur les en-têtes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.detector import (
    VERDICT_DOUBTFUL,
    VERDICT_LEGITIMATE,
    VERDICT_SUSPECT,
    detect,
)
from backend.parser import parse_email


def types_of(result) -> set[str]:
    return {anomaly.type for anomaly in result.anomalies}


def test_display_name_spoof_is_doubtful() -> None:
    raw = 'From: "service@paypal.com" <pirate@evil.ru>\nSubject: urgent'
    result = detect(parse_email(raw))

    assert "display_name_spoof" in types_of(result)
    assert result.verdict == VERDICT_DOUBTFUL


def test_punycode_domain_is_suspect() -> None:
    raw = "From: a@xn--80ak6aa92e.com\nSubject: t"
    result = detect(parse_email(raw))

    assert "punycode_domain" in types_of(result)
    assert result.verdict == VERDICT_SUSPECT


def test_dmarc_misalignment_is_suspect() -> None:
    raw = (
        "From: a@bonnebanque.fr\n"
        "Authentication-Results: x; dkim=pass header.d=evil.com; spf=pass\n"
        "Subject: t"
    )
    result = detect(parse_email(raw))

    assert "dmarc_misalignment" in types_of(result)


def test_dmarc_pass_silences_misalignment() -> None:
    raw = (
        "From: a@bonnebanque.fr\n"
        "Authentication-Results: x; dkim=pass header.d=evil.com; dmarc=pass\n"
        "Subject: t"
    )
    result = detect(parse_email(raw))

    assert "dmarc_misalignment" not in types_of(result)


def test_reply_to_mismatch_is_flagged() -> None:
    raw = "From: Support <support@bonnebanque.fr>\nReply-To: pirate@evil.ru\nSubject: t"
    result = detect(parse_email(raw))

    assert "replyto_mismatch" in types_of(result)


def test_reply_to_to_public_webmail_is_major() -> None:
    raw = (
        "From: Direction <direction@max-bill-schule.de>\n"
        "Reply-To: direction.urgence@gmail.com\n"
        "Subject: t"
    )
    result = detect(parse_email(raw))

    assert "replyto_webmail" in types_of(result)
    assert "replyto_mismatch" not in types_of(result)
    assert result.verdict == VERDICT_DOUBTFUL


def test_recent_domain_is_flagged() -> None:
    recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    result = detect(parse_email("From: a@nouveau.fr\nSubject: t"), domain_created=recent)

    assert "recent_domain" in types_of(result)
    assert result.verdict == VERDICT_SUSPECT


def test_old_domain_is_not_flagged() -> None:
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    result = detect(parse_email("From: a@etabli.fr\nSubject: t"), domain_created=old)

    assert "recent_domain" not in types_of(result)


def test_bulk_suppresses_replyto_mismatch() -> None:
    raw = "\n".join(
        [
            "From: News <news@marque.fr>",
            "Reply-To: contact@autre.fr",
            "List-Unsubscribe: <mailto:unsub@marque.fr>",
            "Subject: t",
        ]
    )
    result = detect(parse_email(raw))

    assert "replyto_mismatch" not in types_of(result)


def test_aligned_message_has_no_phishing_flags() -> None:
    raw = (
        "From: Alice <alice@good.com>\n"
        "Reply-To: alice@good.com\n"
        "Authentication-Results: x; dkim=pass header.d=good.com; dmarc=pass; spf=pass\n"
        "Subject: t"
    )
    result = detect(parse_email(raw))

    assert result.verdict == VERDICT_LEGITIMATE
    assert result.anomalies == []
