from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Literal

from cogniwall.rules.base import Rule
from cogniwall.verdict import Verdict


def _safe_copy(obj: object) -> object:
    """Recursively copy an object, handling only JSON-serializable types.

    Unlike copy.deepcopy, this never invokes __reduce__, __deepcopy__,
    or any other dunder protocol on payload objects, preventing RCE
    via crafted __reduce__ methods and bypasses via custom __deepcopy__.

    Non-JSON-serializable types are converted to their string representation.
    """
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, dict):
        return {_safe_copy(k): _safe_copy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_copy(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_safe_copy(item) for item in obj)
    # Non-JSON-serializable type: convert to string to avoid calling
    # any dunder methods like __reduce__ or __deepcopy__
    return str(obj)


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
            results = await asyncio.gather(
                *[rule.evaluate(_safe_copy(payload)) for rule in tier_rules],
                return_exceptions=True,
            )

            # Convert exceptions to Verdict.error
            verdicts: list[Verdict] = []
            for result, rule in zip(results, tier_rules):
                if isinstance(result, BaseException):
                    # Let CancelledError propagate (it's a BaseException, not Exception)
                    if isinstance(result, asyncio.CancelledError):
                        raise result
                    verdicts.append(
                        Verdict.error(
                            rule=rule.rule_name,
                            error=result,
                        )
                    )
                else:
                    verdicts.append(result)

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
