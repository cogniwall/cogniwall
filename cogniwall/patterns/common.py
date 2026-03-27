from __future__ import annotations

import re

_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b"
)

_PHONE_PATTERN = re.compile(
    r"(?<!\d)"
    r"(?:\+1[-.\s]?)?"
    r"(?:"
    r"\(\d{3}\)[-.\s]?"                # (NNN) with parens
    r"|"
    r"\d{3}[-.\s]"                     # NNN followed by separator (required)
    r")"
    r"\d{3}[-.\s]?"
    r"\d{4}"
    r"(?!\d)"
)


def find_emails(text: str) -> list[str]:
    """Find all email addresses in text."""
    return _EMAIL_PATTERN.findall(text)


def find_phones(text: str) -> list[str]:
    """Find all US phone numbers in text."""
    return [match.group().strip() for match in _PHONE_PATTERN.finditer(text)]
