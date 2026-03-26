from __future__ import annotations

import re


# Zero-width and invisible Unicode characters to strip before matching
_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u034f\u2060\u2061\u2062\u2063\u2064]"
)

# Unicode dashes to normalize to ASCII hyphen
_UNICODE_DASHES = re.compile(
    r"[\u2010\u2011\u2012\u2013\u2014\u2015\ufe58\ufe63\uff0d]"
)


# 13-19 digit sequences, optionally separated by dashes or spaces in groups of 4
# Allow mixed separators (dash, space, or none) between groups
_CC_PATTERN = re.compile(
    r"\b"
    r"(\d{4})([-\s]?)(\d{4})[-\s]?(\d{4})[-\s]?(\d{1,7})"
    r"\b"
)


def _normalize_text(text: str) -> str:
    """Strip invisible chars and normalize unicode dashes to ASCII."""
    text = _INVISIBLE_CHARS.sub("", text)
    text = _UNICODE_DASHES.sub("-", text)
    return text


def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def find_credit_cards(text: str) -> list[str]:
    """Find all credit card numbers in text (Luhn-validated)."""
    normalized = _normalize_text(text)
    results = []
    for match in _CC_PATTERN.finditer(normalized):
        candidate = match.group()
        if _luhn_check(candidate):
            results.append(candidate)
    return results
