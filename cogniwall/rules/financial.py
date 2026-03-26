from __future__ import annotations

import math

from cogniwall.rules.base import Rule, resolve_field
from cogniwall.verdict import Verdict


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
        value = resolve_field(payload, self.field)
        if value is None:
            return Verdict.approved()

        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return Verdict.approved()

        # Python ints can never be NaN or Inf, but math.isnan/isinf on
        # very large ints (e.g. 10**309) raises OverflowError when
        # converting to float. Skip the check for int values.
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return Verdict.blocked(
                rule=self.rule_name,
                reason=f"Financial limit violated: {self.field}={value} is not a finite number",
                details={"field": self.field, "value": value},
            )

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
