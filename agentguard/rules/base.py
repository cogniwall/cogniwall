from __future__ import annotations

from abc import ABC, abstractmethod

from agentguard.verdict import Verdict


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


def extract_strings(obj: object) -> list[str]:
    """Recursively extract all string values from nested dicts/lists.

    Shared utility used by PII and prompt injection rules.
    """
    results: list[str] = []
    _collect_strings(obj, results)
    return results


def _collect_strings(obj: object, acc: list[str]) -> None:
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for value in obj.values():
            _collect_strings(value, acc)
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, acc)
