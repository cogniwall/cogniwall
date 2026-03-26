import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from cogniwall import CogniWall, Verdict, PiiDetectionRule, FinancialLimitRule

FIXTURES = Path(__file__).parent / "fixtures"


class TestCogniWallPython:
    def test_create_with_rules(self):
        guard = CogniWall(rules=[
            PiiDetectionRule(block=["ssn"]),
            FinancialLimitRule(field="amount", max=100),
        ])
        assert guard is not None

    @pytest.mark.asyncio
    async def test_evaluate_async_blocks_pii(self):
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = await guard.evaluate_async({"body": "SSN: 123-45-6789"})
        assert verdict.blocked
        assert verdict.rule == "pii_detection"

    @pytest.mark.asyncio
    async def test_evaluate_async_approves_clean(self):
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = await guard.evaluate_async({"body": "Hello!"})
        assert not verdict.blocked

    def test_evaluate_sync_blocks_pii(self):
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = guard.evaluate({"body": "SSN: 123-45-6789"})
        assert verdict.blocked

    def test_evaluate_sync_approves_clean(self):
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = guard.evaluate({"body": "Hello!"})
        assert not verdict.blocked

    def test_evaluate_invalid_payload_type(self):
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        with pytest.raises(TypeError):
            guard.evaluate("not a dict")

    @pytest.mark.asyncio
    async def test_evaluate_async_invalid_payload_type(self):
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        with pytest.raises(TypeError):
            await guard.evaluate_async("not a dict")

    @pytest.mark.asyncio
    async def test_multi_rule_first_block_wins(self):
        guard = CogniWall(rules=[
            PiiDetectionRule(block=["ssn"]),
            FinancialLimitRule(field="amount", max=100),
        ])
        verdict = await guard.evaluate_async({
            "body": "SSN: 123-45-6789",
            "amount": 500,
        })
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_elapsed_ms_populated(self):
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = await guard.evaluate_async({"body": "Hello"})
        assert verdict.elapsed_ms >= 0


class TestCogniWallFromYAML:
    def test_from_yaml(self):
        guard = CogniWall.from_yaml(FIXTURES / "valid_config.yaml")
        assert guard is not None

    def test_from_yaml_sync_evaluate(self):
        guard = CogniWall.from_yaml(FIXTURES / "valid_config.yaml")
        verdict = guard.evaluate({"body": "SSN: 123-45-6789", "amount": 50})
        assert verdict.blocked
        assert verdict.rule == "pii_detection"


class TestCogniWallOnError:
    @pytest.mark.asyncio
    async def test_on_error_propagated(self):
        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            on_error="block",
        )
        verdict = await guard.evaluate_async({"body": "Hello"})
        assert verdict.status == "approved"
