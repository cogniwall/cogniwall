"""Shared test helpers for robustness test suites."""

import asyncio

from cogniwall.rules.base import Rule
from cogniwall.verdict import Verdict


class FlexibleApproveRule(Rule):
    """Always-approve rule with configurable tier."""

    rule_name = "flex_approve"

    def __init__(self, tier: int = 1):
        self.tier = tier

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict):
        return cls(tier=config.get("tier", 1))


class FlexibleBlockRule(Rule):
    """Always-block rule with configurable tier and name."""

    def __init__(self, tier: int = 1, name: str = "flex_block"):
        self.tier = tier
        self.rule_name = name

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.blocked(rule=self.rule_name, reason="blocked")

    @classmethod
    def from_config(cls, config: dict):
        return cls(tier=config.get("tier", 1))


class SlowApproveRule(Rule):
    """Approve rule with configurable delay."""

    rule_name = "slow_approve"

    def __init__(self, tier: int = 1, delay: float = 0.5):
        self.tier = tier
        self.delay = delay

    async def evaluate(self, payload: dict) -> Verdict:
        await asyncio.sleep(self.delay)
        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict):
        return cls(tier=config.get("tier", 1), delay=config.get("delay", 0.5))


class SlowBlockRule(Rule):
    """Block rule with configurable delay."""

    rule_name = "slow_block"

    def __init__(self, tier: int = 1, delay: float = 0.5):
        self.tier = tier
        self.delay = delay

    async def evaluate(self, payload: dict) -> Verdict:
        await asyncio.sleep(self.delay)
        return Verdict.blocked(rule=self.rule_name, reason="blocked after delay")

    @classmethod
    def from_config(cls, config: dict):
        return cls(tier=config.get("tier", 1), delay=config.get("delay", 0.5))


class FlexibleErrorRule(Rule):
    """Error rule with configurable tier and message."""

    def __init__(self, tier: int = 1, name: str = "flex_error", message: str = "test error"):
        self.tier = tier
        self.rule_name = name
        self._message = message

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.error(rule=self.rule_name, error=RuntimeError(self._message))

    @classmethod
    def from_config(cls, config: dict):
        return cls(tier=config.get("tier", 1))


class RaisingRule(Rule):
    """Rule that raises an exception instead of returning a Verdict."""

    rule_name = "raising_rule"

    def __init__(self, tier: int = 1, exc: BaseException | None = None):
        self.tier = tier
        self._exc = exc or ValueError("rule raised")

    async def evaluate(self, payload: dict) -> Verdict:
        raise self._exc

    @classmethod
    def from_config(cls, config: dict):
        return cls(tier=config.get("tier", 1))


class BadReturnRule(Rule):
    """Rule that returns a non-Verdict value."""

    rule_name = "bad_return"

    def __init__(self, tier: int = 1, return_value=None):
        self.tier = tier
        self._return_value = return_value

    async def evaluate(self, payload: dict):
        return self._return_value

    @classmethod
    def from_config(cls, config: dict):
        return cls(tier=config.get("tier", 1))
