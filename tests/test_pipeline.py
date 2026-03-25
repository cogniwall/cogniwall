import pytest
from agentguard.pipeline import Pipeline
from agentguard.verdict import Verdict
from agentguard.rules.base import Rule


class AlwaysApproveRule(Rule):
    tier = 1
    rule_name = "always_approve"

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict):
        return cls()


class AlwaysBlockRule(Rule):
    tier = 1
    rule_name = "always_block"

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.blocked(rule="always_block", reason="blocked")

    @classmethod
    def from_config(cls, config: dict):
        return cls()


class SlowBlockRule(Rule):
    tier = 2
    rule_name = "slow_block"

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.blocked(rule="slow_block", reason="blocked by tier 2")

    @classmethod
    def from_config(cls, config: dict):
        return cls()


class ErrorRule(Rule):
    tier = 1
    rule_name = "error_rule"

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.error(rule="error_rule", error=RuntimeError("fail"))

    @classmethod
    def from_config(cls, config: dict):
        return cls()


class TestPipeline:
    @pytest.mark.asyncio
    async def test_all_approve(self):
        pipeline = Pipeline(rules=[AlwaysApproveRule(), AlwaysApproveRule()])
        verdict = await pipeline.run({})
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_tier1_blocks_skips_tier2(self):
        pipeline = Pipeline(rules=[AlwaysBlockRule(), SlowBlockRule()])
        verdict = await pipeline.run({})
        assert verdict.blocked
        assert verdict.rule == "always_block"

    @pytest.mark.asyncio
    async def test_tier1_approves_tier2_blocks(self):
        pipeline = Pipeline(rules=[AlwaysApproveRule(), SlowBlockRule()])
        verdict = await pipeline.run({})
        assert verdict.blocked
        assert verdict.rule == "slow_block"

    @pytest.mark.asyncio
    async def test_auto_sorts_by_tier(self):
        """Rules added in wrong order get sorted into correct tiers."""
        pipeline = Pipeline(rules=[SlowBlockRule(), AlwaysApproveRule()])
        # Tier 1 (AlwaysApprove) runs first, then Tier 2 (SlowBlock) blocks
        verdict = await pipeline.run({})
        assert verdict.blocked
        assert verdict.rule == "slow_block"

    @pytest.mark.asyncio
    async def test_empty_rules_approves(self):
        pipeline = Pipeline(rules=[])
        verdict = await pipeline.run({})
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_elapsed_ms_populated(self):
        pipeline = Pipeline(rules=[AlwaysApproveRule()])
        verdict = await pipeline.run({})
        assert verdict.elapsed_ms >= 0


class TestPipelineOnError:
    @pytest.mark.asyncio
    async def test_on_error_default_returns_error(self):
        pipeline = Pipeline(rules=[ErrorRule()], on_error="error")
        verdict = await pipeline.run({})
        assert verdict.status == "error"

    @pytest.mark.asyncio
    async def test_on_error_block(self):
        pipeline = Pipeline(rules=[ErrorRule()], on_error="block")
        verdict = await pipeline.run({})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_on_error_approve(self):
        pipeline = Pipeline(rules=[ErrorRule()], on_error="approve")
        verdict = await pipeline.run({})
        assert verdict.status == "approved"
