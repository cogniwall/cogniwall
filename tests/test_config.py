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
