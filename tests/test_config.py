import pytest
from pathlib import Path
from cogniwall.config import load_config, CogniWallConfigError
from cogniwall.audit import AuditClient

FIXTURES = Path(__file__).parent / "fixtures"


class TestLoadConfig:
    def test_load_valid_config(self):
        result = load_config(FIXTURES / "valid_config.yaml")
        assert result["on_error"] == "block"
        assert len(result["rules"]) == 3

    def test_rules_are_rule_instances(self):
        from cogniwall.rules.pii import PiiDetectionRule
        from cogniwall.rules.financial import FinancialLimitRule
        from cogniwall.rules.prompt_injection import PromptInjectionRule

        result = load_config(FIXTURES / "valid_config.yaml")
        rules = result["rules"]
        assert isinstance(rules[0], PiiDetectionRule)
        assert isinstance(rules[1], FinancialLimitRule)
        assert isinstance(rules[2], PromptInjectionRule)

    def test_default_on_error(self):
        """If on_error is not specified, default to 'error'."""
        from cogniwall.config import parse_config
        result = parse_config({"version": "1", "rules": []})
        assert result["on_error"] == "error"


class TestConfigValidation:
    def test_unknown_rule_type(self):
        with pytest.raises(CogniWallConfigError, match="nonexistent_rule"):
            load_config(FIXTURES / "invalid_unknown_type.yaml")

    def test_missing_required_field(self):
        with pytest.raises(CogniWallConfigError, match="field"):
            load_config(FIXTURES / "invalid_missing_field.yaml")

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config(FIXTURES / "does_not_exist.yaml")

    def test_invalid_on_error_value(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="on_error"):
            parse_config({"version": "1", "on_error": "panic", "rules": []})

    def test_negative_financial_max(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="max"):
            parse_config({
                "version": "1",
                "rules": [{"type": "financial_limit", "field": "amount", "max": -50}],
            })


class TestToneSentimentValidation:
    def test_missing_field(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="field"):
            parse_config({
                "version": "1",
                "rules": [{"type": "tone_sentiment", "block": ["angry"]}],
            })

    def test_invalid_preset(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="invalid_tone"):
            parse_config({
                "version": "1",
                "rules": [{"type": "tone_sentiment", "field": "body", "block": ["invalid_tone"]}],
            })

    def test_no_block_or_custom(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="block.*custom"):
            parse_config({
                "version": "1",
                "rules": [{"type": "tone_sentiment", "field": "body"}],
            })

    def test_valid_config(self):
        from cogniwall.config import parse_config
        result = parse_config({
            "version": "1",
            "rules": [{"type": "tone_sentiment", "field": "body", "block": ["angry"], "custom": ["legally liable"], "api_key": "sk-test"}],
        })
        assert len(result["rules"]) == 1


class TestRateLimitValidation:
    def test_missing_max_actions(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="max_actions"):
            parse_config({
                "version": "1",
                "rules": [{"type": "rate_limit", "window_seconds": 60}],
            })

    def test_missing_window_seconds(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="window_seconds"):
            parse_config({
                "version": "1",
                "rules": [{"type": "rate_limit", "max_actions": 5}],
            })

    def test_negative_window(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="window_seconds"):
            parse_config({
                "version": "1",
                "rules": [{"type": "rate_limit", "max_actions": 5, "window_seconds": -1}],
            })

    def test_valid_config(self):
        from cogniwall.config import parse_config
        result = parse_config({
            "version": "1",
            "rules": [{"type": "rate_limit", "max_actions": 5, "window_seconds": 3600}],
        })
        assert len(result["rules"]) == 1


class TestProviderValidation:
    def test_unknown_provider_rejected(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="Unknown provider"):
            parse_config({
                "version": "1",
                "rules": [{
                    "type": "prompt_injection",
                    "provider": "nonexistent",
                    "api_key": "sk-test",
                }],
            })

    def test_invalid_base_url_type_rejected(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="base_url"):
            parse_config({
                "version": "1",
                "rules": [{
                    "type": "prompt_injection",
                    "provider": "openai",
                    "base_url": 12345,
                    "api_key": "sk-test",
                }],
            })

    def test_valid_provider_accepted(self):
        from cogniwall.config import parse_config
        result = parse_config({
            "version": "1",
            "rules": [{
                "type": "prompt_injection",
                "provider": "openai",
                "api_key": "sk-test",
            }],
        })
        assert len(result["rules"]) == 1

    def test_valid_base_url_accepted(self):
        from cogniwall.config import parse_config
        result = parse_config({
            "version": "1",
            "rules": [{
                "type": "prompt_injection",
                "provider": "openai",
                "base_url": "http://127.0.0.1:11434/v1",
            }],
        })
        assert len(result["rules"]) == 1


class TestAuditConfigParsing:
    def test_parse_config_with_audit(self):
        from cogniwall.config import parse_config
        result = parse_config({
            "version": "1",
            "rules": [],
            "audit": {
                "endpoint": "http://localhost:3000/api/events",
                "include_payload": True,
                "flush_mode": "sync",
            },
        })
        assert isinstance(result["audit"], AuditClient)
        assert result["audit"].endpoint == "http://localhost:3000/api/events"
        assert result["audit"].include_payload is True
        assert result["audit"].flush_mode == "sync"

    def test_parse_config_without_audit(self):
        from cogniwall.config import parse_config
        result = parse_config({"version": "1", "rules": []})
        assert result["audit"] is None

    def test_audit_missing_endpoint(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="endpoint"):
            parse_config({
                "version": "1",
                "rules": [],
                "audit": {"include_payload": True},
            })

    def test_audit_invalid_flush_mode(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="flush_mode"):
            parse_config({
                "version": "1",
                "rules": [],
                "audit": {
                    "endpoint": "http://localhost:3000/api/events",
                    "flush_mode": "invalid",
                },
            })
