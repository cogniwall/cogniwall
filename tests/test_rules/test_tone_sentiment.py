import pytest
from unittest.mock import AsyncMock, patch
from agentguard.rules.tone_sentiment import ToneSentimentRule, VALID_PRESETS


@pytest.fixture
def tone_rule():
    return ToneSentimentRule(
        field="body",
        block=["angry", "sarcastic"],
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        api_key="test-key",
    )


class TestTonePresets:
    @pytest.mark.asyncio
    async def test_blocks_angry_tone(self, tone_rule):
        with patch.object(tone_rule, "_call_llm", new_callable=AsyncMock, return_value="angry"):
            verdict = await tone_rule.evaluate({"body": "This is absolutely unacceptable!"})
            assert verdict.blocked
            assert verdict.rule == "tone_sentiment"
            assert verdict.details["tone"] == "angry"
            assert verdict.details["field"] == "body"

    @pytest.mark.asyncio
    async def test_approves_neutral_tone(self, tone_rule):
        with patch.object(tone_rule, "_call_llm", new_callable=AsyncMock, return_value="NONE"):
            verdict = await tone_rule.evaluate({"body": "Here is your order status."})
            assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_blocks_sarcastic_tone(self, tone_rule):
        with patch.object(tone_rule, "_call_llm", new_callable=AsyncMock, return_value="sarcastic"):
            verdict = await tone_rule.evaluate({"body": "Oh sure, that's just great."})
            assert verdict.blocked
            assert verdict.details["tone"] == "sarcastic"


class TestToneCustom:
    @pytest.mark.asyncio
    async def test_custom_tone_detected(self):
        rule = ToneSentimentRule(
            field="body",
            custom=["sounds legally liable"],
            provider="anthropic",
            api_key="test-key",
        )
        with patch.object(rule, "_call_llm", new_callable=AsyncMock, return_value="sounds legally liable"):
            verdict = await rule.evaluate({"body": "We accept full responsibility."})
            assert verdict.blocked
            assert verdict.details["tone"] == "sounds legally liable"

    @pytest.mark.asyncio
    async def test_presets_and_custom_combined(self):
        rule = ToneSentimentRule(
            field="body",
            block=["angry"],
            custom=["promises a timeline"],
            provider="anthropic",
            api_key="test-key",
        )
        with patch.object(rule, "_call_llm", new_callable=AsyncMock, return_value="promises a timeline"):
            verdict = await rule.evaluate({"body": "We'll have it done by Friday."})
            assert verdict.blocked


class TestToneFieldResolution:
    @pytest.mark.asyncio
    async def test_missing_field_approves(self, tone_rule):
        verdict = await tone_rule.evaluate({"other": "data"})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_non_string_field_approves(self, tone_rule):
        verdict = await tone_rule.evaluate({"body": 42})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_nested_field(self):
        rule = ToneSentimentRule(
            field="message.content",
            block=["angry"],
            provider="anthropic",
            api_key="test-key",
        )
        with patch.object(rule, "_call_llm", new_callable=AsyncMock, return_value="angry"):
            verdict = await rule.evaluate({"message": {"content": "I'm furious!"}})
            assert verdict.blocked


class TestToneErrors:
    @pytest.mark.asyncio
    async def test_llm_error_returns_error_verdict(self, tone_rule):
        with patch.object(
            tone_rule, "_call_llm", new_callable=AsyncMock, side_effect=RuntimeError("API timeout")
        ):
            verdict = await tone_rule.evaluate({"body": "Hello"})
            assert verdict.status == "error"
            assert isinstance(verdict.error, RuntimeError)


class TestToneFromConfig:
    def test_from_config_with_presets(self):
        rule = ToneSentimentRule.from_config({
            "field": "body",
            "block": ["angry", "sarcastic"],
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key_env": "OPENAI_API_KEY",
        })
        assert isinstance(rule, ToneSentimentRule)
        assert rule.field == "body"
        assert rule.block == ["angry", "sarcastic"]

    def test_from_config_with_custom(self):
        rule = ToneSentimentRule.from_config({
            "field": "body",
            "custom": ["sounds legally liable"],
        })
        assert isinstance(rule, ToneSentimentRule)

    def test_from_config_defaults(self):
        rule = ToneSentimentRule.from_config({
            "field": "body",
            "block": ["angry"],
        })
        assert rule.provider == "anthropic"


class TestValidPresets:
    def test_valid_presets_exported(self):
        assert "angry" in VALID_PRESETS
        assert "sarcastic" in VALID_PRESETS
        assert "apologetic" in VALID_PRESETS
        assert "threatening" in VALID_PRESETS
        assert "dismissive" in VALID_PRESETS
