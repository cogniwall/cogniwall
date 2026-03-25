from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Literal

from agentguard.rules.base import Rule
from agentguard.verdict import Verdict


class Pipeline:
    def __init__(
        self,
        rules: list[Rule],
        on_error: Literal["error", "block", "approve"] = "error",
    ):
        self.on_error = on_error
        self.tiers = self._sort_into_tiers(rules)

    async def run(self, payload: dict) -> Verdict:
        start = time.perf_counter()

        for tier_rules in self.tiers:
            verdicts = await asyncio.gather(
                *[rule.evaluate(payload) for rule in tier_rules]
            )

            # Handle errors first
            errors = [v for v in verdicts if v.status == "error"]
            if errors:
                error_verdict = errors[0]
                elapsed = (time.perf_counter() - start) * 1000
                verdict = self._handle_error(error_verdict, elapsed)
                return verdict

            # Check for blocks
            blocked = [v for v in verdicts if v.blocked]
            if blocked:
                elapsed = (time.perf_counter() - start) * 1000
                v = blocked[0]
                return Verdict.blocked(
                    rule=v.rule,
                    reason=v.reason,
                    details=v.details,
                    elapsed_ms=elapsed,
                )

        elapsed = (time.perf_counter() - start) * 1000
        return Verdict.approved(elapsed_ms=elapsed)

    def _handle_error(self, error_verdict: Verdict, elapsed_ms: float) -> Verdict:
        if self.on_error == "block":
            return Verdict.blocked(
                rule=error_verdict.rule,
                reason=f"Error treated as block: {error_verdict.error}",
                details={"original_error": str(error_verdict.error)},
                elapsed_ms=elapsed_ms,
            )
        elif self.on_error == "approve":
            return Verdict.approved(elapsed_ms=elapsed_ms)
        else:
            return Verdict.error(
                rule=error_verdict.rule,
                error=error_verdict.error,
                elapsed_ms=elapsed_ms,
            )

    @staticmethod
    def _sort_into_tiers(rules: list[Rule]) -> list[list[Rule]]:
        if not rules:
            return []
        tier_map: dict[int, list[Rule]] = defaultdict(list)
        for rule in rules:
            tier_map[rule.tier].append(rule)
        return [tier_map[k] for k in sorted(tier_map.keys())]
