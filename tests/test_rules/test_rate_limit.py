import asyncio

import pytest
from agentguard.rules.rate_limit import RateLimitRule


class TestRateLimitRule:
    @pytest.mark.asyncio
    async def test_allows_within_limit(self):
        rule = RateLimitRule(max_actions=3, window_seconds=60)
        for _ in range(3):
            verdict = await rule.evaluate({"user_id": "user_1"})
            assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_blocks_over_limit(self):
        rule = RateLimitRule(max_actions=3, window_seconds=60)
        for _ in range(3):
            await rule.evaluate({"user_id": "user_1"})
        verdict = await rule.evaluate({"user_id": "user_1"})
        assert verdict.blocked
        assert verdict.rule == "rate_limit"
        assert verdict.details["count"] == 3
        assert verdict.details["max_actions"] == 3

    @pytest.mark.asyncio
    async def test_per_key_isolation(self):
        rule = RateLimitRule(max_actions=2, window_seconds=60, key_field="user_id")
        for _ in range(2):
            await rule.evaluate({"user_id": "user_a"})
        assert (await rule.evaluate({"user_id": "user_a"})).blocked
        assert not (await rule.evaluate({"user_id": "user_b"})).blocked

    @pytest.mark.asyncio
    async def test_global_mode(self):
        rule = RateLimitRule(max_actions=2, window_seconds=60)
        await rule.evaluate({"data": "first"})
        await rule.evaluate({"data": "second"})
        verdict = await rule.evaluate({"data": "third"})
        assert verdict.blocked
        assert verdict.details["key"] == "__global__"

    @pytest.mark.asyncio
    async def test_window_expiry(self):
        rule = RateLimitRule(max_actions=2, window_seconds=0.1)
        await rule.evaluate({"data": "first"})
        await rule.evaluate({"data": "second"})
        await asyncio.sleep(0.15)
        verdict = await rule.evaluate({"data": "third"})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_missing_key_field_approves(self):
        rule = RateLimitRule(max_actions=1, window_seconds=60, key_field="user_id")
        verdict = await rule.evaluate({"other": "data"})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        rule = RateLimitRule(max_actions=5, window_seconds=60)
        verdicts = await asyncio.gather(
            *[rule.evaluate({"data": f"action_{i}"}) for i in range(10)]
        )
        approved = sum(1 for v in verdicts if not v.blocked)
        blocked = sum(1 for v in verdicts if v.blocked)
        assert approved == 5
        assert blocked == 5


class TestRateLimitFromConfig:
    def test_from_config(self):
        rule = RateLimitRule.from_config({
            "max_actions": 10,
            "window_seconds": 3600,
            "key_field": "agent_id",
        })
        assert isinstance(rule, RateLimitRule)

    def test_from_config_global(self):
        rule = RateLimitRule.from_config({
            "max_actions": 100,
            "window_seconds": 60,
        })
        assert isinstance(rule, RateLimitRule)
