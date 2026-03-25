import pytest
from agentguard.rules.pii import PiiDetectionRule


@pytest.fixture
def pii_rule():
    return PiiDetectionRule(block=["ssn", "credit_card", "email", "phone"])


class TestPiiDetectionRule:
    @pytest.mark.asyncio
    async def test_blocks_ssn(self, pii_rule):
        verdict = await pii_rule.evaluate({"body": "SSN: 123-45-6789"})
        assert verdict.blocked
        assert verdict.rule == "pii_detection"
        assert "ssn" in verdict.reason.lower()

    @pytest.mark.asyncio
    async def test_blocks_credit_card(self, pii_rule):
        verdict = await pii_rule.evaluate({"body": "Card: 4111111111111111"})
        assert verdict.blocked
        assert "credit_card" in verdict.reason.lower() or "credit card" in verdict.reason.lower()

    @pytest.mark.asyncio
    async def test_blocks_email(self, pii_rule):
        verdict = await pii_rule.evaluate({"body": "Email: user@example.com"})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_blocks_phone(self, pii_rule):
        verdict = await pii_rule.evaluate({"body": "Call 555-123-4567"})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_approves_clean_payload(self, pii_rule):
        verdict = await pii_rule.evaluate({"body": "Hello, how can I help?"})
        assert not verdict.blocked
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_scans_nested_dicts(self, pii_rule):
        payload = {"data": {"inner": {"text": "SSN: 123-45-6789"}}}
        verdict = await pii_rule.evaluate(payload)
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_scans_lists(self, pii_rule):
        payload = {"items": ["safe", "SSN: 123-45-6789"]}
        verdict = await pii_rule.evaluate(payload)
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_custom_terms(self):
        rule = PiiDetectionRule(block=[], custom_terms=["Project Titan"])
        verdict = await rule.evaluate({"body": "Update on Project Titan"})
        assert verdict.blocked
        assert "Project Titan" in verdict.details["matched"]

    @pytest.mark.asyncio
    async def test_selective_block_types(self):
        """Only blocks types listed in `block`."""
        rule = PiiDetectionRule(block=["ssn"])
        verdict = await rule.evaluate({"body": "Email: user@example.com"})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_empty_payload(self, pii_rule):
        verdict = await pii_rule.evaluate({})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_non_string_values_skipped(self, pii_rule):
        verdict = await pii_rule.evaluate({"count": 42, "active": True, "data": None})
        assert not verdict.blocked


class TestPiiFromConfig:
    def test_from_config(self):
        rule = PiiDetectionRule.from_config({
            "block": ["ssn", "credit_card"],
            "custom_terms": ["Secret"],
        })
        assert isinstance(rule, PiiDetectionRule)
