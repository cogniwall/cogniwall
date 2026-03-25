from __future__ import annotations

import re


# 13-19 digit sequences, optionally separated by dashes or spaces in groups of 4
_CC_PATTERN = re.compile(
    r"\b"
    r"(\d{4})([-\s]?)(\d{4})\2(\d{4})\2(\d{1,7})"
    r"\b"
)


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
    results = []
    for match in _CC_PATTERN.finditer(text):
        candidate = match.group()
        if _luhn_check(candidate):
            results.append(candidate)
    return results
