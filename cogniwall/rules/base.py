from __future__ import annotations

from abc import ABC, abstractmethod

from cogniwall.verdict import Verdict


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


def extract_strings(obj: object) -> list[str]:
    """Iteratively extract all string values from nested dicts/lists.

    Shared utility used by PII and prompt injection rules.
    Uses a stack-based approach with cycle detection to handle
    deeply nested and circular structures safely.
    """
    results: list[str] = []
    # Stack of (object, depth) tuples
    stack: list[tuple[object, int]] = [(obj, 0)]
    visited: set[int] = set()

    while stack:
        current, depth = stack.pop()

        if depth > _MAX_DEPTH:
            continue

        if isinstance(current, str):
            results.append(current)
        elif isinstance(current, bytes):
            try:
                results.append(current.decode("utf-8", errors="replace"))
            except Exception:
                pass
        elif isinstance(current, dict):
            obj_id = id(current)
            if obj_id in visited:
                continue
            visited.add(obj_id)
            for value in current.values():
                stack.append((value, depth + 1))
        elif isinstance(current, (list, tuple)):
            obj_id = id(current)
            if obj_id in visited:
                continue
            visited.add(obj_id)
            for item in current:
                stack.append((item, depth + 1))
        elif isinstance(current, (set, frozenset)):
            obj_id = id(current)
            if obj_id in visited:
                continue
            visited.add(obj_id)
            for item in current:
                stack.append((item, depth + 1))

    return results


def resolve_field(payload: dict, field_path: str) -> object:
    """Resolve a dot-notation field path in a nested dict.

    Returns None if any segment is missing or not a dict.
    Shared utility used by financial, tone/sentiment, and rate limit rules.
    """
    current = payload
    for segment in field_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
        if current is None:
            return None
    return current
