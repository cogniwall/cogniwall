import pytest
from pathlib import Path
from agentguard.config import load_config, AgentGuardConfigError

FIXTURES = Path(__file__).parent / "fixtures"


class TestLoadConfig:
    def test_load_valid_config(self):
        result = load_config(FIXTURES / "valid_config.yaml")
        assert result["on_error"] == "block"
        assert len(result["rules"]) == 3

    def test_rules_are_rule_instances(self):
        from agentguard.rules.pii import PiiDetectionRule
        from agentguard.rules.financial import FinancialLimitRule
        from agentguard.rules.prompt_injection import PromptInjectionRule

        result = load_config(FIXTURES / "valid_config.yaml")
        rules = result["rules"]
        assert isinstance(rules[0], PiiDetectionRule)
        assert isinstance(rules[1], FinancialLimitRule)
        assert isinstance(rules[2], PromptInjectionRule)

    def test_default_on_error(self):
        """If on_error is not specified, default to 'error'."""
        from agentguard.config import parse_config
        result = parse_config({"version": "1", "rules": []})
        assert result["on_error"] == "error"


class TestConfigValidation:
    def test_unknown_rule_type(self):
        with pytest.raises(AgentGuardConfigError, match="nonexistent_rule"):
            load_config(FIXTURES / "invalid_unknown_type.yaml")

    def test_missing_required_field(self):
        with pytest.raises(AgentGuardConfigError, match="field"):
            load_config(FIXTURES / "invalid_missing_field.yaml")

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config(FIXTURES / "does_not_exist.yaml")

    def test_invalid_on_error_value(self):
        from agentguard.config import parse_config
        with pytest.raises(AgentGuardConfigError, match="on_error"):
            parse_config({"version": "1", "on_error": "panic", "rules": []})

    def test_negative_financial_max(self):
        from agentguard.config import parse_config
        with pytest.raises(AgentGuardConfigError, match="max"):
            parse_config({
                "version": "1",
                "rules": [{"type": "financial_limit", "field": "amount", "max": -50}],
            })


class TestToneSentimentValidation:
    def test_missing_field(self):
        from agentguard.config import parse_config
        with pytest.raises(AgentGuardConfigError, match="field"):
            parse_config({
                "version": "1",
                "rules": [{"type": "tone_sentiment", "block": ["angry"]}],
            })

    def test_invalid_preset(self):
        from agentguard.config import parse_config
        with pytest.raises(AgentGuardConfigError, match="invalid_tone"):
            parse_config({
                "version": "1",
                "rules": [{"type": "tone_sentiment", "field": "body", "block": ["invalid_tone"]}],
            })

    def test_no_block_or_custom(self):
        from agentguard.config import parse_config
        with pytest.raises(AgentGuardConfigError, match="block.*custom"):
            parse_config({
                "version": "1",
                "rules": [{"type": "tone_sentiment", "field": "body"}],
            })

    def test_valid_config(self):
        from agentguard.config import parse_config
        result = parse_config({
            "version": "1",
            "rules": [{"type": "tone_sentiment", "field": "body", "block": ["angry"], "custom": ["legally liable"]}],
        })
        assert len(result["rules"]) == 1


class TestRateLimitValidation:
    def test_missing_max_actions(self):
        from agentguard.config import parse_config
        with pytest.raises(AgentGuardConfigError, match="max_actions"):
            parse_config({
                "version": "1",
                "rules": [{"type": "rate_limit", "window_seconds": 60}],
            })

    def test_missing_window_seconds(self):
        from agentguard.config import parse_config
        with pytest.raises(AgentGuardConfigError, match="window_seconds"):
            parse_config({
                "version": "1",
                "rules": [{"type": "rate_limit", "max_actions": 5}],
            })

    def test_negative_window(self):
        from agentguard.config import parse_config
        with pytest.raises(AgentGuardConfigError, match="window_seconds"):
            parse_config({
                "version": "1",
                "rules": [{"type": "rate_limit", "max_actions": 5, "window_seconds": -1}],
            })

    def test_valid_config(self):
        from agentguard.config import parse_config
        result = parse_config({
            "version": "1",
            "rules": [{"type": "rate_limit", "max_actions": 5, "window_seconds": 3600}],
        })
        assert len(result["rules"]) == 1
