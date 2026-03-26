from __future__ import annotations

import asyncio
import time

from cogniwall.rules.base import Rule, resolve_field
from cogniwall.verdict import Verdict


class RateLimitRule(Rule):
    tier = 1
    rule_name = "rate_limit"

    def __init__(
        self,
        max_actions: int,
        window_seconds: float,
        key_field: str | None = None,
    ):
        self.max_actions = max_actions
        self.window_seconds = window_seconds
        self.key_field = key_field
        self._timestamps: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def evaluate(self, payload: dict) -> Verdict:
        if self.key_field:
            key = resolve_field(payload, self.key_field)
            if key is None:
                return Verdict.approved()
            key = str(key)
        else:
            key = "__global__"

        now = time.monotonic()
        cutoff = now - self.window_seconds

        async with self._lock:
            timestamps = self._timestamps.get(key, [])
            timestamps = [t for t in timestamps if t > cutoff]

            if not timestamps and key in self._timestamps:
                del self._timestamps[key]

            if len(timestamps) >= self.max_actions:
                self._timestamps[key] = timestamps
                return Verdict.blocked(
                    rule=self.rule_name,
                    reason=f"Rate limit exceeded: {self.max_actions} actions in {self.window_seconds}s for key '{key}'",
                    details={
                        "key": key,
                        "count": len(timestamps),
                        "max_actions": self.max_actions,
                        "window_seconds": self.window_seconds,
                    },
                )

            timestamps.append(now)
            self._timestamps[key] = timestamps
            return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> RateLimitRule:
        return cls(
            max_actions=config["max_actions"],
            window_seconds=config["window_seconds"],
            key_field=config.get("key_field"),
        )
