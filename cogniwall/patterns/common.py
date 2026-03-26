from __future__ import annotations

import re

_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

_PHONE_PATTERN = re.compile(
    r"(?:\+1[-.\s]?)?"          # optional country code
    r"(?:\(?\d{3}\)?[-.\s]?)"   # area code
    r"\d{3}[-.\s]?"             # exchange
    r"\d{4}"                    # subscriber
    r"\b"
)


def find_emails(text: str) -> list[str]:
    """Find all email addresses in text."""
    return _EMAIL_PATTERN.findall(text)


def find_phones(text: str) -> list[str]:
    """Find all US phone numbers in text."""
    return [match.group().strip() for match in _PHONE_PATTERN.finditer(text)]
