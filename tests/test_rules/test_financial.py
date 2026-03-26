import pytest
from cogniwall.rules.financial import FinancialLimitRule


class TestFinancialLimitRule:
    @pytest.mark.asyncio
    async def test_blocks_over_max(self):
        rule = FinancialLimitRule(field="amount", max=100)
        verdict = await rule.evaluate({"amount": 500})
        assert verdict.blocked
        assert verdict.rule == "financial_limit"
        assert "500" in str(verdict.details)

    @pytest.mark.asyncio
    async def test_approves_under_max(self):
        rule = FinancialLimitRule(field="amount", max=100)
        verdict = await rule.evaluate({"amount": 50})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_approves_equal_to_max(self):
        rule = FinancialLimitRule(field="amount", max=100)
        verdict = await rule.evaluate({"amount": 100})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_blocks_under_min(self):
        rule = FinancialLimitRule(field="amount", min=10)
        verdict = await rule.evaluate({"amount": 5})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_range_check(self):
        rule = FinancialLimitRule(field="amount", min=10, max=100)
        assert (await rule.evaluate({"amount": 5})).blocked
        assert not (await rule.evaluate({"amount": 50})).blocked
        assert (await rule.evaluate({"amount": 500})).blocked

    @pytest.mark.asyncio
    async def test_nested_field_dot_notation(self):
        rule = FinancialLimitRule(field="data.refund.amount", max=100)
        payload = {"data": {"refund": {"amount": 500}}}
        verdict = await rule.evaluate(payload)
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_missing_field_approves(self):
        rule = FinancialLimitRule(field="amount", max=100)
        verdict = await rule.evaluate({"other": "data"})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_non_numeric_field_approves(self):
        rule = FinancialLimitRule(field="amount", max=100)
        verdict = await rule.evaluate({"amount": "not a number"})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_float_value(self):
        rule = FinancialLimitRule(field="amount", max=100)
        verdict = await rule.evaluate({"amount": 100.01})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_empty_payload(self):
        rule = FinancialLimitRule(field="amount", max=100)
        verdict = await rule.evaluate({})
        assert not verdict.blocked


class TestFinancialFromConfig:
    def test_from_config_max_only(self):
        rule = FinancialLimitRule.from_config({"field": "amount", "max": 100})
        assert isinstance(rule, FinancialLimitRule)

    def test_from_config_min_and_max(self):
        rule = FinancialLimitRule.from_config({"field": "price", "min": 1, "max": 999})
        assert isinstance(rule, FinancialLimitRule)
