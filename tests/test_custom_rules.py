import re
import pytest
from agentguard import AgentGuard, Verdict
from agentguard.rules.base import Rule, extract_strings, resolve_field
from agentguard.rules.pii import PiiDetectionRule


class NoProfanityRule(Rule):
    """Example custom Tier 1 rule."""
    tier = 1
    rule_name = "no_profanity"
    BLOCKED_WORDS = {"damn", "hell"}

    async def evaluate(self, payload: dict) -> Verdict:
        texts = extract_strings(payload)
        for text in texts:
            for word in self.BLOCKED_WORDS:
                if re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
                    return Verdict.blocked(
                        rule=self.rule_name,
                        reason=f"Profanity detected: {word}",
                    )
        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> "NoProfanityRule":
        return cls()


class CustomFieldCheckRule(Rule):
    """Example custom Tier 1 rule using resolve_field."""
    tier = 1
    rule_name = "custom_field_check"

    async def evaluate(self, payload: dict) -> Verdict:
        status = resolve_field(payload, "order.status")
        if status == "cancelled":
            return Verdict.blocked(
                rule=self.rule_name,
                reason="Cannot act on cancelled orders",
            )
        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> "CustomFieldCheckRule":
        return cls()


class CustomTier2Rule(Rule):
    """Example custom Tier 2 rule."""
    tier = 2
    rule_name = "custom_tier2"

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.blocked(rule=self.rule_name, reason="always blocks")

    @classmethod
    def from_config(cls, config: dict) -> "CustomTier2Rule":
        return cls()


class CustomErrorRule(Rule):
    """Custom rule that always errors."""
    tier = 1
    rule_name = "custom_error"

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.error(rule=self.rule_name, error=RuntimeError("custom failure"))

    @classmethod
    def from_config(cls, config: dict) -> "CustomErrorRule":
        return cls()


class TestCustomRuleInPipeline:
    @pytest.mark.asyncio
    async def test_custom_tier1_alongside_builtin(self):
        guard = AgentGuard(rules=[
            NoProfanityRule(),
            PiiDetectionRule(block=["ssn"]),
        ])
        verdict = await guard.evaluate_async({"body": "damn it"})
        assert verdict.blocked
        assert verdict.rule == "no_profanity"

    @pytest.mark.asyncio
    async def test_custom_tier2_sorted_correctly(self):
        guard = AgentGuard(rules=[
            CustomTier2Rule(),
            PiiDetectionRule(block=["ssn"]),
        ])
        verdict = await guard.evaluate_async({"body": "clean text"})
        assert verdict.blocked
        assert verdict.rule == "custom_tier2"

    @pytest.mark.asyncio
    async def test_custom_error_handled_by_on_error(self):
        guard = AgentGuard(rules=[CustomErrorRule()], on_error="block")
        verdict = await guard.evaluate_async({"body": "hello"})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_custom_rule_uses_resolve_field(self):
        guard = AgentGuard(rules=[CustomFieldCheckRule()])
        verdict = await guard.evaluate_async({"order": {"status": "cancelled"}})
        assert verdict.blocked
        assert verdict.rule == "custom_field_check"

    @pytest.mark.asyncio
    async def test_custom_rule_uses_extract_strings(self):
        guard = AgentGuard(rules=[NoProfanityRule()])
        verdict = await guard.evaluate_async({"nested": {"text": "go to hell"}})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_mixed_builtin_and_custom(self):
        guard = AgentGuard(rules=[
            PiiDetectionRule(block=["ssn"]),
            NoProfanityRule(),
            CustomFieldCheckRule(),
        ])
        verdict = await guard.evaluate_async({"body": "Hello", "order": {"status": "active"}})
        assert not verdict.blocked
