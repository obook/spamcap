"""Tests unitaires de backend.parser.

Les fixtures sont construites ligne par ligne pour que les lignes de
continuation repliées (celles qui commencent par une tabulation) soient sans
ambiguïté.
"""

from __future__ import annotations

from backend.parser import (
    BODY_PREVIEW_CHARS,
    parse_email,
    split_and_truncate,
)

LEGITIMATE = "\n".join(
    [
        "Received: from mx.recipient.com (mx.recipient.com [203.0.113.10])",
        "\tby mail.recipient.com (Postfix) with ESMTPS id 4ABCDE",
        "\tfor <user@recipient.com>; Tue, 01 Jan 2026 10:00:05 +0000",
        "Received: from smtp.sender.com (smtp.sender.com [198.51.100.20])",
        "\tby mx.recipient.com (Postfix) with ESMTP id 1ZZZZZ",
        "\tfor <user@recipient.com>; Tue, 01 Jan 2026 10:00:00 +0000",
        "From: Alice <alice@sender.com>",
        "To: user@recipient.com",
        "Subject: Hello",
        "Message-ID: <abc123@sender.com>",
        "Authentication-Results: mx.recipient.com; spf=pass "
        "smtp.mailfrom=sender.com; dkim=pass header.d=sender.com; dmarc=pass",
        "Received-SPF: pass (sender.com: domain of sender.com designates "
        "198.51.100.20 as permitted sender)",
        "DKIM-Signature: v=1; a=rsa-sha256; d=sender.com; s=sel; h=from:to:subject",
    ]
)


def test_hops_are_reversed_to_chronological_order() -> None:
    result = parse_email(LEGITIMATE)

    assert len(result.hops) == 2
    # Le saut 0 est le serveur d'origine, placé en bas de la chaîne brute.
    assert result.hops[0].from_ip == "198.51.100.20"
    assert result.hops[1].from_ip == "203.0.113.10"
    assert result.hops[0].index == 0
    assert result.hops[1].index == 1


def test_timestamps_are_parsed_and_increasing() -> None:
    result = parse_email(LEGITIMATE)

    first = result.hops[0].timestamp
    second = result.hops[1].timestamp
    assert first is not None and second is not None
    assert first < second


def test_informational_headers_extracted() -> None:
    result = parse_email(LEGITIMATE)

    assert result.from_header == "Alice <alice@sender.com>"
    assert result.to_header == "user@recipient.com"
    assert result.subject == "Hello"
    assert result.message_id == "<abc123@sender.com>"


def test_authentication_headers_extracted() -> None:
    result = parse_email(LEGITIMATE)

    assert result.authentication_results is not None
    assert "spf=pass" in result.authentication_results
    assert result.received_spf is not None
    assert result.received_spf.startswith("pass")
    assert len(result.dkim_signatures) == 1
    assert "d=sender.com" in result.dkim_signatures[0]


def test_ipv6_in_brackets() -> None:
    raw = "\n".join(
        [
            "Received: from mail6.sender.com (mail6.sender.com [IPv6:2001:db8::1])",
            "\tby mx.recipient.com with ESMTPS id X; Tue, 01 Jan 2026 10:00:00 +0000",
            "Subject: v6",
        ]
    )
    result = parse_email(raw)

    assert result.hops[0].from_ip == "2001:db8::1"


def test_malformed_received_does_not_crash() -> None:
    raw = "\n".join(
        [
            "Received: total garbage with no structure at all",
            "Subject: broken",
        ]
    )
    result = parse_email(raw)

    assert len(result.hops) == 1
    assert result.hops[0].from_ip is None
    assert result.hops[0].timestamp is None
    assert result.subject == "broken"


def test_no_received_field() -> None:
    raw = "\n".join(
        [
            "From: self@example.com",
            "To: self@example.com",
            "Subject: local message",
        ]
    )
    result = parse_email(raw)

    assert result.hops == []
    assert result.subject == "local message"


def test_encoded_subject_is_decoded() -> None:
    raw = "Subject: =?UTF-8?B?w4ljb2xl?=\nFrom: a@b.com"
    result = parse_email(raw)

    assert result.subject == "École"


def test_originating_ip_extracted() -> None:
    raw = "From: a@b.com\nX-Originating-IP: [192.168.1.50]\nSubject: t"
    result = parse_email(raw)

    assert result.originating_ip == "192.168.1.50"


def test_originating_ip_fallback_header() -> None:
    raw = "From: a@b.com\nX-Sender-IP: 81.2.69.142\nSubject: t"
    result = parse_email(raw)

    assert result.originating_ip == "81.2.69.142"


def test_return_path_extracted() -> None:
    raw = "From: a@b.fr\nReturn-Path: <bounce@b.fr>\nSubject: t"
    result = parse_email(raw)

    assert result.return_path == "<bounce@b.fr>"


def test_bulk_newsletter_detected() -> None:
    raw = "\n".join(
        [
            "From: a@b.fr",
            "Subject: news",
            "List-Id: ma liste <list.b.fr>",
            "List-Unsubscribe: <mailto:unsub@b.fr>,<https://b.fr/unsub>",
            "X-Mailer: Sendinblue",
        ]
    )
    result = parse_email(raw)

    assert result.bulk.is_bulk is True
    assert result.bulk.esp == "Sendinblue"
    assert result.bulk.unsubscribe == "https://b.fr/unsub"


def test_body_is_truncated_to_preview() -> None:
    headers = "Subject: with body\nFrom: a@b.com"
    body = "x" * 5000
    raw = headers + "\n\n" + body

    result = parse_email(raw)

    assert result.truncated is True
    assert len(result.body_preview) == BODY_PREVIEW_CHARS
    assert result.analyzed_size_bytes < result.raw_size_bytes


def test_headers_only_is_not_truncated() -> None:
    raw = "Subject: headers only\nFrom: a@b.com"

    split = split_and_truncate(raw)

    assert split.truncated is False
    assert split.body_preview == ""
    assert split.analyzed_size_bytes == split.raw_size_bytes
