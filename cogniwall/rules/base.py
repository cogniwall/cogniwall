from __future__ import annotations

import base64 as _base64
import collections
import dataclasses
import html as _html
import re as _re
import unicodedata as _unicodedata
from abc import ABC, abstractmethod
from collections.abc import Iterable
from urllib.parse import unquote as _url_unquote

from cogniwall.verdict import Verdict

# Zero-width and invisible Unicode characters
_INVISIBLE_RE = _re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u034f"
    r"\u2060\u2061\u2062\u2063\u2064\u180e\x00]"
)

# Leetspeak mapping
_LEET_MAP = str.maketrans("013457@", "oieasst")


def strip_invisible(text: str) -> str:
    """Remove zero-width, null bytes, and other invisible characters."""
    return _INVISIBLE_RE.sub("", text)


def normalize_unicode(text: str) -> str:
    """NFKD normalize and strip combining marks (accents, diacritics)."""
    decomposed = _unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not _unicodedata.combining(c))


def normalize_for_matching(text: str) -> str:
    """Full normalization pipeline: invisible chars, NFKD, strip combining."""
    return normalize_unicode(strip_invisible(text))


def decode_obfuscation(text: str) -> str:
    """Decode common text obfuscation: HTML entities, URL encoding."""
    text = _html.unescape(text)
    text = _url_unquote(text)
    return text


def leet_normalize(text: str) -> str:
    """Normalize leetspeak substitutions back to ASCII."""
    return text.translate(_LEET_MAP)


def try_base64_decode(text: str) -> str | None:
    """Attempt base64 decoding. Returns decoded text or None."""
    stripped = text.strip()
    if len(stripped) < 8 or len(stripped) % 4 != 0:
        return None
    try:
        decoded = _base64.b64decode(stripped, validate=True)
        result = decoded.decode("utf-8", errors="strict")
        if sum(c.isprintable() or c.isspace() for c in result) / max(len(result), 1) > 0.8:
            return result
    except Exception:
        pass
    return None


class Rule(ABC):
    """Base class for all guardrail rules.

    Subclasses must set:
        tier: int — 1 for classical/fast rules, 2 for LLM-based rules
        rule_name: str — identifier used in verdicts and config
    """

    tier: int
    rule_name: str

    @abstractmethod
    async def evaluate(self, payload: dict) -> Verdict:
        """Evaluate a payload and return a Verdict."""
        ...

    @classmethod
    @abstractmethod
    def from_config(cls, config: dict) -> Rule:
        """Construct a rule instance from a YAML/dict config."""
        ...


_MAX_DEPTH = 2000


def extract_strings(obj: object, *, include_keys: bool = False) -> list[str]:
    """Iteratively extract all string values from nested dicts/lists.

    Shared utility used by PII and prompt injection rules.
    Uses a stack-based approach with cycle detection to handle
    deeply nested and circular structures safely.

    Args:
        obj: The object to extract strings from.
        include_keys: If True, also extract strings from dict keys.
            Callers that need to scan dict keys for sensitive data
            (e.g. PII detection) should set this to True.
    """
    results: list[str] = []
    # Stack of (object, depth) tuples
    stack: list[tuple[object, int]] = [(obj, 0)]
    visited: set[int] = set()

    while stack:
        current, depth = stack.pop()

        if depth > _MAX_DEPTH:
            continue

        if current is None or isinstance(current, (bool, int, float)):
            continue
        elif isinstance(current, str):
            results.append(current)
        elif isinstance(current, (bytes, bytearray)):
            try:
                results.append(current.decode("utf-8", errors="replace"))
            except Exception:
                pass
        elif isinstance(current, memoryview):
            try:
                results.append(current.tobytes().decode("utf-8", errors="replace"))
            except Exception:
                pass
        elif isinstance(current, dict):
            obj_id = id(current)
            if obj_id in visited:
                continue
            visited.add(obj_id)
            for key, value in current.items():
                if include_keys:
                    stack.append((key, depth + 1))
                stack.append((value, depth + 1))
        elif isinstance(current, (list, tuple, set, frozenset, collections.deque)):
            obj_id = id(current)
            if obj_id in visited:
                continue
            visited.add(obj_id)
            for item in current:
                stack.append((item, depth + 1))
        elif dataclasses.is_dataclass(current) and not isinstance(current, type):
            obj_id = id(current)
            if obj_id in visited:
                continue
            visited.add(obj_id)
            for field in dataclasses.fields(current):
                stack.append((getattr(current, field.name), depth + 1))
        elif isinstance(current, Iterable):
            # Fallback for generators, custom iterables, etc.
            try:
                for item in current:
                    stack.append((item, depth + 1))
            except Exception:
                pass
        else:
            # Objects with __str__
            try:
                text = str(current)
                # Avoid useless default repr strings
                if text and not text.startswith("<"):
                    results.append(text)
            except Exception:
                pass

    return results


def resolve_field(payload: dict, field_path: str) -> object:
    """Resolve a dot-notation field path in a nested dict.

    Returns None if any segment is missing or not a dict.
    Shared utility used by financial, tone/sentiment, and rate limit rules.
    """
    # Check if the full path exists as a literal key
    if isinstance(payload, dict) and field_path in payload:
        return payload[field_path]

    current = payload
    for segment in field_path.split("."):
        if isinstance(current, dict):
            current = current.get(segment)
        elif isinstance(current, (list, tuple)) and current:
            current = current[0]
            if isinstance(current, dict):
                current = current.get(segment)
            else:
                return None
        else:
            return None
        if current is None:
            return None
    return current
