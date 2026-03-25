from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agentguard.rules.base import Rule
from agentguard.rules.financial import FinancialLimitRule
from agentguard.rules.pii import PiiDetectionRule
from agentguard.rules.prompt_injection import PromptInjectionRule
from agentguard.rules.tone_sentiment import ToneSentimentRule, VALID_PRESETS
from agentguard.rules.rate_limit import RateLimitRule


class AgentGuardConfigError(Exception):
    """Raised when configuration is invalid."""
    pass


_RULE_REGISTRY: dict[str, type[Rule]] = {
    "pii_detection": PiiDetectionRule,
    "financial_limit": FinancialLimitRule,
    "prompt_injection": PromptInjectionRule,
    "tone_sentiment": ToneSentimentRule,
    "rate_limit": RateLimitRule,
}

_VALID_ON_ERROR = {"error", "block", "approve"}


def load_config(path: str | Path) -> dict[str, Any]:
    """Load and validate an AgentGuard YAML config file."""
    path = Path(path)
    with open(path) as f:
        try:
            raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise AgentGuardConfigError(f"YAML syntax error in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise AgentGuardConfigError(f"Config file {path} must be a YAML mapping")

    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate a raw config dict."""
    on_error = raw.get("on_error", "error")
    if on_error not in _VALID_ON_ERROR:
        raise AgentGuardConfigError(
            f"Invalid on_error value: '{on_error}'. Must be one of: {_VALID_ON_ERROR}"
        )

    raw_rules = raw.get("rules", [])
    rules = []
    for i, rule_config in enumerate(raw_rules):
        rule_type = rule_config.get("type")
        if rule_type not in _RULE_REGISTRY:
            raise AgentGuardConfigError(
                f"Unknown rule type '{rule_type}' at rules[{i}]. "
                f"Available types: {list(_RULE_REGISTRY.keys())}"
            )

        rule_cls = _RULE_REGISTRY[rule_type]

        try:
            _validate_rule_config(rule_type, rule_config)
            rule = rule_cls.from_config(rule_config)
        except AgentGuardConfigError:
            raise
        except Exception as e:
            raise AgentGuardConfigError(
                f"Error constructing rule '{rule_type}' at rules[{i}]: {e}"
            ) from e

        rules.append(rule)

    return {"rules": rules, "on_error": on_error}


def _validate_rule_config(rule_type: str, config: dict) -> None:
    """Validate rule-specific config before construction."""
    if rule_type == "financial_limit":
        if "field" not in config:
            raise AgentGuardConfigError(
                "financial_limit rule requires 'field' parameter"
            )
        if "max" in config and config["max"] is not None and config["max"] < 0:
            raise AgentGuardConfigError(
                f"financial_limit 'max' must be non-negative, got {config['max']}"
            )
        if "min" in config and config["min"] is not None and config["min"] < 0:
            raise AgentGuardConfigError(
                f"financial_limit 'min' must be non-negative, got {config['min']}"
            )
    elif rule_type == "tone_sentiment":
        if "field" not in config:
            raise AgentGuardConfigError(
                "tone_sentiment rule requires 'field' parameter"
            )
        block = config.get("block", [])
        custom = config.get("custom", [])
        if not block and not custom:
            raise AgentGuardConfigError(
                "tone_sentiment rule requires at least one of 'block' or 'custom'"
            )
        for preset in block:
            if preset not in VALID_PRESETS:
                raise AgentGuardConfigError(
                    f"Invalid tone preset '{preset}'. "
                    f"Available presets: {sorted(VALID_PRESETS)}"
                )
    elif rule_type == "rate_limit":
        if "max_actions" not in config:
            raise AgentGuardConfigError(
                "rate_limit rule requires 'max_actions' parameter"
            )
        if "window_seconds" not in config:
            raise AgentGuardConfigError(
                "rate_limit rule requires 'window_seconds' parameter"
            )
        if config["window_seconds"] <= 0:
            raise AgentGuardConfigError(
                f"rate_limit 'window_seconds' must be positive, got {config['window_seconds']}"
            )
