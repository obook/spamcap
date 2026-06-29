"""Détection du filtre anti-spam du fournisseur et de son verdict."""

from __future__ import annotations

from email.message import Message

from .models import FilterVerdict, MICROSOFT_SPAM_SCL
from .text import collapse, group, to_int


def detect_filter(message: Message) -> FilterVerdict:
    """Détecte le fournisseur de filtrage et normalise son verdict.

    Les détecteurs sont essayés dans l'ordre ; le premier qui reconnaît ses
    en-têtes l'emporte. Ajouter un fournisseur revient à écrire une fonction
    de plus et à l'ajouter à cette liste.
    """

    detectors = (_microsoft_filter, _spamassassin_filter, _proxad_filter)
    for detect_one in detectors:
        verdict = detect_one(message)
        if verdict is not None:
            return verdict
    return FilterVerdict()


def _microsoft_filter(message: Message) -> FilterVerdict | None:
    """Normalise les en-têtes anti-spam de Microsoft 365 / Exchange.

    SCL (Spam Confidence Level) et AuthAs ont des en-têtes dédiés ; BCL (Bulk
    Complaint Level) est niché dans "X-Microsoft-Antispam" ; SFV est dans
    "X-Forefront-Antispam-Report", qui porte aussi parfois SCL en repli.
    """

    scl = to_int(message.get("X-MS-Exchange-Organization-SCL"))
    auth_as = message.get("X-MS-Exchange-Organization-AuthAs") or None

    antispam = collapse(message.get("X-Microsoft-Antispam") or "")
    bcl = to_int(group(r"\bBCL:(-?\d+)", antispam))

    forefront = collapse(message.get("X-Forefront-Antispam-Report") or "")
    if scl is None:
        scl = to_int(group(r"\bSCL:(-?\d+)", forefront))
    sfv = group(r"\bSFV:(\w+)", forefront)

    if scl is None and bcl is None and sfv is None and auth_as is None:
        return None

    is_spam: bool | None = None
    if scl is not None:
        is_spam = scl >= MICROSOFT_SPAM_SCL
    if sfv == "SPM":
        is_spam = True

    details: list[str] = []
    if scl is not None:
        details.append(f"SCL {scl}")
    if bcl is not None:
        details.append(f"BCL {bcl}")
    if sfv:
        details.append(f"SFV {sfv}")
    if auth_as:
        details.append(f"AuthAs {auth_as}")

    score = f"SCL {scl}" if scl is not None else None
    return FilterVerdict(
        source="Microsoft 365", is_spam=is_spam, score=score, details=details
    )


def _spamassassin_filter(message: Message) -> FilterVerdict | None:
    """Normalise les en-têtes SpamAssassin (X-Spam-*), très répandus.

    "X-Spam-Flag: YES" tranche le verdict ; "X-Spam-Status" porte le mot-clé
    et le score ("score=2.3 required=5.0") ; "X-Spam-Score" est un repli.
    """

    flag = message.get("X-Spam-Flag")
    status = collapse(message.get("X-Spam-Status") or "")
    score_header = message.get("X-Spam-Score")

    if not (flag or status or score_header):
        return None

    is_spam: bool | None = None
    if flag:
        is_spam = flag.strip().upper() == "YES"
    elif status:
        verdict_word = group(r"^(\w+)", status)
        if verdict_word:
            is_spam = verdict_word.lower() == "yes"

    raw_score = group(r"score=(-?[\d.]+)", status) or (
        score_header.strip() if score_header else None
    )
    required = group(r"required=(-?[\d.]+)", status)
    if raw_score and required:
        score = f"score {raw_score}/{required}"
    elif raw_score:
        score = f"score {raw_score}"
    else:
        score = None

    details: list[str] = []
    if is_spam is not None:
        details.append("spam" if is_spam else "non-spam")
    if score:
        details.append(score)

    return FilterVerdict(
        source="SpamAssassin", is_spam=is_spam, score=score, details=details
    )


def _proxad_filter(message: Message) -> FilterVerdict | None:
    """Normalise le verdict du filtre de Free / Proxad ("X-ProXaD-SC").

    Format typique : "state=HAM:CommercialEmailGeneric score=17".
    """

    value = collapse(message.get("X-ProXaD-SC") or "")
    if not value:
        return None

    state = group(r"state=([A-Za-z]+)", value)
    category = group(r"state=[A-Za-z]+:(\S+)", value)
    score = group(r"score=(-?\d+)", value)

    is_spam: bool | None = None
    if state:
        is_spam = state.upper() == "SPAM"

    details: list[str] = []
    if state:
        details.append(f"{state}:{category}" if category else state)
    if score:
        details.append(f"score {score}")

    return FilterVerdict(
        source="Proxad/Free",
        is_spam=is_spam,
        score=f"score {score}" if score else None,
        details=details,
    )
