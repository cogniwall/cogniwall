from __future__ import annotations

import re
import unicodedata

# SSN formats: 123-45-6789, 123 45 6789, 123.45.6789, 123456789
# Area number (first 3) cannot be 000, 666, or 900-999
# Allow mixed separators (dash, space, dot, or none) in either position
_SSN_PATTERN = re.compile(
    r"(?<!\d)(?!000|666|9\d{2})"
    r"(\d{3})"
    r"([-\s.,]?)"
    r"(?!00)\d{2}"
    r"[-\s.,]?"
    r"(?!0000)\d{4}"
    r"(?!\d)"
)

# Zero-width and invisible Unicode characters to strip before matching
_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u034f\u2060\u2061\u2062\u2063\u2064]"
)

# Unicode dashes to normalize to ASCII hyphen
_UNICODE_DASHES = re.compile(
    r"[\u2010\u2011\u2012\u2013\u2014\u2015\ufe58\ufe63\uff0d]"
)


def _normalize_text(text: str) -> str:
    """Strip invisible chars, normalize unicode dashes and digits to ASCII."""
    text = unicodedata.normalize("NFKD", text)
    text = _INVISIBLE_CHARS.sub("", text)
    text = _UNICODE_DASHES.sub("-", text)
    return text


def find_ssns(text: str) -> list[str]:
    """Find all SSN-like patterns in text."""
    normalized = _normalize_text(text)
    return [match.group() for match in _SSN_PATTERN.finditer(normalized)]
