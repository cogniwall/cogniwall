from __future__ import annotations

import math
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from cogniwall.audit import AuditClient
from cogniwall.rules.base import Rule
from cogniwall.rules.financial import FinancialLimitRule
from cogniwall.rules.pii import PiiDetectionRule
from cogniwall.rules.prompt_injection import PromptInjectionRule
from cogniwall.rules.tone_sentiment import ToneSentimentRule, VALID_PRESETS
from cogniwall.rules.rate_limit import RateLimitRule


class CogniWallConfigError(Exception):
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
    """Load and validate an CogniWall YAML config file."""
    path = Path(path)
    with open(path) as f:
        try:
            raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise CogniWallConfigError(f"YAML syntax error in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise CogniWallConfigError(f"Config file {path} must be a YAML mapping")

    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate a raw config dict."""
    on_error = raw.get("on_error", "error")
    if on_error not in _VALID_ON_ERROR:
        raise CogniWallConfigError(
            f"Invalid on_error value: '{on_error}'. Must be one of: {_VALID_ON_ERROR}"
        )

    raw_rules = raw.get("rules", [])
    rules = []
    for i, rule_config in enumerate(raw_rules):
        rule_type = rule_config.get("type")
        if rule_type not in _RULE_REGISTRY:
            raise CogniWallConfigError(
                f"Unknown rule type '{rule_type}' at rules[{i}]. "
                f"Available types: {list(_RULE_REGISTRY.keys())}"
            )

        rule_cls = _RULE_REGISTRY[rule_type]

        try:
            _validate_rule_config(rule_type, rule_config)
            rule = rule_cls.from_config(rule_config)
        except CogniWallConfigError:
            raise
        except Exception as e:
            raise CogniWallConfigError(
                f"Error constructing rule '{rule_type}' at rules[{i}]: {e}"
            ) from e

        rules.append(rule)

    # Parse audit config
    audit = None
    raw_audit = raw.get("audit")
    if raw_audit:
        _validate_audit_config(raw_audit)
        audit = AuditClient.from_config(raw_audit)

    return {"rules": rules, "on_error": on_error, "audit": audit}


def _validate_rule_config(rule_type: str, config: dict) -> None:
    """Validate rule-specific config before construction."""
    if rule_type == "financial_limit":
        if "field" not in config:
            raise CogniWallConfigError(
                "financial_limit rule requires 'field' parameter"
            )
        if "max" in config and config["max"] is not None:
            if isinstance(config["max"], float) and math.isnan(config["max"]):
                raise CogniWallConfigError(
                    "financial_limit 'max' must not be NaN"
                )
            if config["max"] < 0:
                raise CogniWallConfigError(
                    f"financial_limit 'max' must be non-negative, got {config['max']}"
                )
        if "min" in config and config["min"] is not None:
            if isinstance(config["min"], float) and math.isnan(config["min"]):
                raise CogniWallConfigError(
                    "financial_limit 'min' must not be NaN"
                )
            if config["min"] < 0:
                raise CogniWallConfigError(
                    f"financial_limit 'min' must be non-negative, got {config['min']}"
                )
    elif rule_type == "tone_sentiment":
        if "field" not in config:
            raise CogniWallConfigError(
                "tone_sentiment rule requires 'field' parameter"
            )
        block = config.get("block", [])
        custom = config.get("custom", [])
        if not block and not custom:
            raise CogniWallConfigError(
                "tone_sentiment rule requires at least one of 'block' or 'custom'"
            )
        for preset in block:
            if preset not in VALID_PRESETS:
                raise CogniWallConfigError(
                    f"Invalid tone preset '{preset}'. "
                    f"Available presets: {sorted(VALID_PRESETS)}"
                )
    elif rule_type == "rate_limit":
        if "max_actions" not in config:
            raise CogniWallConfigError(
                "rate_limit rule requires 'max_actions' parameter"
            )
        if config["max_actions"] <= 0:
            raise CogniWallConfigError(
                f"rate_limit 'max_actions' must be positive, got {config['max_actions']}"
            )
        if "window_seconds" not in config:
            raise CogniWallConfigError(
                "rate_limit rule requires 'window_seconds' parameter"
            )
        if config["window_seconds"] <= 0:
            raise CogniWallConfigError(
                f"rate_limit 'window_seconds' must be positive, got {config['window_seconds']}"
            )


def _validate_audit_config(config: dict) -> None:
    """Validate the audit configuration section."""
    if "endpoint" not in config:
        raise CogniWallConfigError(
            "audit config requires 'endpoint' parameter"
        )
    parsed = urlparse(config["endpoint"])
    if parsed.scheme not in ("http", "https"):
        raise CogniWallConfigError(
            f"audit 'endpoint' must use http or https, got '{parsed.scheme}'"
        )
    flush_mode = config.get("flush_mode", "async")
    if flush_mode not in ("async", "sync"):
        raise CogniWallConfigError(
            f"audit 'flush_mode' must be 'async' or 'sync', got '{flush_mode}'"
        )
    flush_interval = config.get("flush_interval", 5.0)
    if not isinstance(flush_interval, (int, float)) or flush_interval <= 0:
        raise CogniWallConfigError(
            f"audit 'flush_interval' must be a positive number, got {flush_interval}"
        )
    batch_size = config.get("batch_size", 50)
    if not isinstance(batch_size, int) or batch_size <= 0:
        raise CogniWallConfigError(
            f"audit 'batch_size' must be a positive integer, got {batch_size}"
        )
