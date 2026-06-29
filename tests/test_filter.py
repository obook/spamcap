"""Tests unitaires du verdict de filtre (Microsoft 365 et SpamAssassin)."""

from __future__ import annotations

from backend.detector import VERDICT_LEGITIMATE, VERDICT_SUSPECT, detect
from backend.parser import parse_email


def test_microsoft_clean_message() -> None:
    raw = "\n".join(
        [
            "From: a@exemple.fr",
            "Subject: interne",
            "X-MS-Exchange-Organization-SCL: 1",
            "X-MS-Exchange-Organization-AuthAs: Internal",
            "X-Microsoft-Antispam: BCL:0;ARA:1234;",
        ]
    )
    parsed = parse_email(raw)

    assert parsed.filter_verdict.source == "Microsoft 365"
    assert parsed.filter_verdict.is_spam is False
    assert parsed.filter_verdict.score == "SCL 1"
    assert "AuthAs Internal" in parsed.filter_verdict.details
    assert detect(parsed).verdict == VERDICT_LEGITIMATE


def test_microsoft_high_scl_is_suspect() -> None:
    raw = "From: a@b.fr\nSubject: t\nX-MS-Exchange-Organization-SCL: 6"
    parsed = parse_email(raw)
    result = detect(parsed)

    assert parsed.filter_verdict.is_spam is True
    assert result.verdict == VERDICT_SUSPECT
    assert any(a.type == "filter_spam" for a in result.anomalies)


def test_spamassassin_flagged_is_suspect() -> None:
    raw = "\n".join(
        [
            "From: a@b.com",
            "Subject: pub",
            "X-Spam-Flag: YES",
            "X-Spam-Status: Yes, score=8.1 required=5.0 tests=BAYES_99",
            "X-Spam-Score: 8.1",
        ]
    )
    parsed = parse_email(raw)
    result = detect(parsed)

    assert parsed.filter_verdict.source == "SpamAssassin"
    assert parsed.filter_verdict.is_spam is True
    assert parsed.filter_verdict.score == "score 8.1/5.0"
    assert result.verdict == VERDICT_SUSPECT


def test_spamassassin_clean_message() -> None:
    raw = "From: a@b.com\nSubject: ok\nX-Spam-Status: No, score=-1.2 required=5.0"
    parsed = parse_email(raw)

    assert parsed.filter_verdict.source == "SpamAssassin"
    assert parsed.filter_verdict.is_spam is False
    assert detect(parsed).verdict == VERDICT_LEGITIMATE


def test_proxad_ham_is_clean() -> None:
    raw = "From: a@b.fr\nSubject: t\nX-ProXaD-SC: state=HAM:CommercialEmailGeneric score=17"
    parsed = parse_email(raw)

    assert parsed.filter_verdict.source == "Proxad/Free"
    assert parsed.filter_verdict.is_spam is False
    assert parsed.filter_verdict.score == "score 17"
    assert detect(parsed).verdict == VERDICT_LEGITIMATE


def test_proxad_spam_is_suspect() -> None:
    raw = "From: a@b.fr\nSubject: t\nX-ProXaD-SC: state=SPAM:Phishing score=99"
    parsed = parse_email(raw)

    assert parsed.filter_verdict.is_spam is True
    assert detect(parsed).verdict == VERDICT_SUSPECT


def test_no_filter_headers() -> None:
    parsed = parse_email("From: a@b.com\nSubject: rien")

    assert parsed.filter_verdict.source is None
    assert parsed.filter_verdict.is_spam is None
    assert detect(parsed).anomalies == []
