from __future__ import annotations

import re

# SSN formats: 123-45-6789, 123 45 6789, 123456789
# Area number (first 3) cannot be 000, 666, or 900-999
_SSN_PATTERN = re.compile(
    r"\b(?!000|666|9\d{2})"  # area number restrictions (000, 666, 900-999 invalid)
    r"(\d{3})"               # area number
    r"([-\s]?)"              # separator (dash, space, or none)
    r"(?!00)\d{2}"           # group number (not 00)
    r"\2"                    # same separator
    r"(?!0000)\d{4}"         # serial number (not 0000)
    r"\b"
)


def find_ssns(text: str) -> list[str]:
    """Find all SSN-like patterns in text."""
    return [match.group() for match in _SSN_PATTERN.finditer(text)]
