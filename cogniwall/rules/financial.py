from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation

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

        if isinstance(value, (list, tuple)):
            for item in value:
                v = await self._check_value(item)
                if v.blocked:
                    return v
            return Verdict.approved()

        return await self._check_value(value)

    async def _check_value(self, value: object) -> Verdict:
        if isinstance(value, bool):
            return Verdict.approved()

        if isinstance(value, str):
            try:
                value = float(value)
            except (ValueError, OverflowError):
                return Verdict.approved()

        if isinstance(value, Decimal):
            try:
                value = float(value)
            except (ValueError, OverflowError, InvalidOperation):
                return Verdict.approved()

        if isinstance(value, complex):
            value = value.real

        if not isinstance(value, (int, float)):
            return Verdict.approved()

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

        # Block suspiciously large negative amounts when only max is configured
        if self.min_value is None and self.max_value is not None and value < 0:
            if abs(value) > self.max_value:
                return Verdict.blocked(
                    rule=self.rule_name,
                    reason=f"Financial limit violated: {self.field}={value} is a suspicious negative amount",
                    details={"field": self.field, "value": value, "max": self.max_value},
                )

        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> FinancialLimitRule:
        return cls(
            field=config["field"],
            max=config.get("max"),
            min=config.get("min"),
        )
