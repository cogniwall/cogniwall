from __future__ import annotations

from agentguard.rules.base import Rule
from agentguard.verdict import Verdict


class FinancialLimitRule(Rule):
    tier = 1
    rule_name = "financial_limit"

    def __init__(
        self,
        field: str,
        max: float | None = None,
        min: float | None = None,
    ):
        self.field = field
        self.max_value = max
        self.min_value = min

    async def evaluate(self, payload: dict) -> Verdict:
        value = _resolve_field(payload, self.field)
        if value is None:
            return Verdict.approved()

        if not isinstance(value, (int, float)):
            return Verdict.approved()

        if self.max_value is not None and value > self.max_value:
            return Verdict.blocked(
                rule=self.rule_name,
                reason=f"Financial limit exceeded: {self.field}={value} > max={self.max_value}",
                details={"field": self.field, "value": value, "max": self.max_value},
            )

        if self.min_value is not None and value < self.min_value:
            return Verdict.blocked(
                rule=self.rule_name,
                reason=f"Financial limit violated: {self.field}={value} < min={self.min_value}",
                details={"field": self.field, "value": value, "min": self.min_value},
            )

        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> FinancialLimitRule:
        return cls(
            field=config["field"],
            max=config.get("max"),
            min=config.get("min"),
        )


def _resolve_field(payload: dict, field_path: str) -> object:
    """Resolve a dot-notation field path in a nested dict.

    Returns None if any segment is missing or not a dict.
    """
    current = payload
    for segment in field_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
        if current is None:
            return None
    return current
