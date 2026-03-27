"""Config fuzzing tests — edge cases in parsing, extreme parameters, unicode, and conflicts."""

import asyncio
import time

import pytest

from cogniwall import CogniWall, PiiDetectionRule, FinancialLimitRule, RateLimitRule
from cogniwall.config import parse_config, CogniWallConfigError


# ---------------------------------------------------------------------------
# Empty and minimal configs
# ---------------------------------------------------------------------------


class TestEmptyAndMinimalConfigs:
    """Verify parse_config handles empty, minimal, and malformed inputs."""

    def test_empty_dict_config(self):
        """Empty dict yields on_error='error', rules=[], audit=None."""
        result = parse_config({})
        assert result["on_error"] == "error"
        assert result["rules"] == []
        assert result["audit"] is None

    def test_config_with_only_version(self):
        """Unrecognized top-level keys like 'version' are silently ignored."""
        result = parse_config({"version": "1"})
        assert result["on_error"] == "error"
        assert result["rules"] == []
        assert result["audit"] is None

    def test_config_with_empty_rules_list(self):
        """Explicit empty rules list works identically to missing rules key."""
        result = parse_config({"rules": []})
        assert result["rules"] == []
        assert result["on_error"] == "error"

    def test_config_with_none_rules(self):
        """rules=None causes enumerate(None) which raises TypeError."""
        with pytest.raises(TypeError):
            parse_config({"rules": None})

    def test_config_with_rules_as_dict(self):
        """rules as a dict: enumerate yields keys, .get('type') fails on str."""
        with pytest.raises((AttributeError, CogniWallConfigError)):
            parse_config({"rules": {"type": "pii_detection"}})

    def test_config_with_rules_as_string(self):
        """rules as a string: iterates characters, char.get('type') fails."""
        with pytest.raises((AttributeError, CogniWallConfigError)):
            parse_config({"rules": "pii_detection"})

    def test_config_with_rules_as_integer(self):
        """rules as an integer: enumerate(42) raises TypeError."""
        with pytest.raises(TypeError):
            parse_config({"rules": 42})


# ---------------------------------------------------------------------------
# Conflicting rules
# ---------------------------------------------------------------------------


class TestConflictingRules:
    """Verify behavior when multiple rules overlap or conflict."""

    @pytest.mark.asyncio
    async def test_two_financial_rules_conflicting_limits(self):
        """Two financial rules on the same field with incompatible ranges.

        Rule 1: max=100, Rule 2: min=200.  Any value is blocked by at least
        one rule.  Tier-1 rules run in parallel; the first block wins.
        """
        config = parse_config({
            "rules": [
                {"type": "financial_limit", "field": "amount", "max": 100},
                {"type": "financial_limit", "field": "amount", "min": 200},
            ]
        })
        wall = CogniWall(rules=config["rules"], on_error=config["on_error"])

        # 150 exceeds max=100 from rule 1
        verdict = await wall.evaluate_async({"amount": 150})
        assert verdict.blocked

        # 250 also exceeds max=100 from rule 1
        verdict = await wall.evaluate_async({"amount": 250})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_duplicate_rule_types_accepted(self):
        """Two pii_detection rules with different block lists both fire."""
        config = parse_config({
            "rules": [
                {"type": "pii_detection", "block": ["ssn"]},
                {"type": "pii_detection", "block": ["email"]},
            ]
        })
        assert len(config["rules"]) == 2

        wall = CogniWall(rules=config["rules"], on_error=config["on_error"])
        verdict = await wall.evaluate_async({"body": "SSN: 123-45-6789"})
        assert verdict.blocked
        assert verdict.rule == "pii_detection"

    @pytest.mark.asyncio
    async def test_rate_limit_and_pii_same_tier(self):
        """rate_limit and pii_detection are both tier 1; clean payload approved."""
        config = parse_config({
            "rules": [
                {"type": "rate_limit", "max_actions": 100, "window_seconds": 60},
                {"type": "pii_detection", "block": ["ssn"]},
            ]
        })
        wall = CogniWall(rules=config["rules"], on_error=config["on_error"])
        verdict = await wall.evaluate_async({"body": "hello world"})
        assert verdict.status == "approved"


# ---------------------------------------------------------------------------
# Extreme parameter values
# ---------------------------------------------------------------------------


class TestExtremeParameterValues:
    """Push rule parameters to extremes to find overflow or precision issues."""

    @pytest.mark.asyncio
    async def test_financial_max_zero(self):
        """max=0: value 0 is approved (0 > 0 is false), 0.01 is blocked."""
        rule = FinancialLimitRule(field="amount", max=0)
        verdict = await rule.evaluate({"amount": 0})
        assert verdict.status == "approved"

        verdict = await rule.evaluate({"amount": 0.01})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_financial_max_very_large(self):
        """max=10**18: values near the boundary behave correctly."""
        rule = FinancialLimitRule(field="amount", max=10**18)

        verdict = await rule.evaluate({"amount": 10**18 - 1})
        assert verdict.status == "approved"

        verdict = await rule.evaluate({"amount": 10**18 + 1})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_financial_max_float_precision(self):
        """max=0.1+0.2: demonstrates IEEE 754 precision behavior.

        0.1 + 0.2 = 0.30000000000000004 in IEEE 754.
        0.3 > 0.30000000000000004 is False, so {"amount": 0.3} is approved.
        """
        rule = FinancialLimitRule(field="amount", max=0.1 + 0.2)
        verdict = await rule.evaluate({"amount": 0.3})
        # 0.3 > 0.30000000000000004 is False — approved
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_rate_limit_max_actions_very_large(self):
        """max_actions=10**9: a single evaluation is well under the limit."""
        rule = RateLimitRule(max_actions=10**9, window_seconds=1)
        verdict = await rule.evaluate({})
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_rate_limit_window_very_small(self):
        """window_seconds=0.001: window expires almost immediately."""
        rule = RateLimitRule(max_actions=1, window_seconds=0.001)

        verdict = await rule.evaluate({})
        assert verdict.status == "approved"

        # Wait for the tiny window to expire
        await asyncio.sleep(0.01)

        verdict = await rule.evaluate({})
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_rate_limit_window_very_large(self):
        """window_seconds=1 year: second evaluation is blocked."""
        rule = RateLimitRule(max_actions=1, window_seconds=86400 * 365)

        verdict = await rule.evaluate({})
        assert verdict.status == "approved"

        verdict = await rule.evaluate({})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_pii_block_empty_list(self):
        """block=[]: no scanners enabled, so nothing is ever detected."""
        rule = PiiDetectionRule(block=[])
        verdict = await rule.evaluate({"body": "SSN: 123-45-6789"})
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_pii_block_all_types(self):
        """All PII scanner types enabled — each type triggers a block."""
        rule = PiiDetectionRule(block=["ssn", "credit_card", "email", "phone"])

        verdict = await rule.evaluate({"body": "SSN: 123-45-6789"})
        assert verdict.blocked

        verdict = await rule.evaluate({"body": "contact: user@example.com"})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_pii_custom_terms_very_long(self):
        """A 10,000-char custom term is matched correctly."""
        long_term = "a" * 10000
        rule = PiiDetectionRule(custom_terms=[long_term])

        verdict = await rule.evaluate({"body": long_term})
        assert verdict.blocked

        verdict = await rule.evaluate({"body": "hello"})
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_pii_custom_terms_1000_entries(self):
        """1000 custom terms: the last term is still matched within 2 seconds."""
        terms = [f"term_{i}" for i in range(1000)]
        rule = PiiDetectionRule(custom_terms=terms)

        start = time.perf_counter()
        verdict = await rule.evaluate({"body": "term_999"})
        elapsed = time.perf_counter() - start

        assert verdict.blocked
        assert elapsed < 2.0, f"Expected <2s, took {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# Unicode in config
# ---------------------------------------------------------------------------


class TestUnicodeInConfig:
    """Verify that Unicode field names, custom terms, and emoji work correctly."""

    @pytest.mark.asyncio
    async def test_financial_field_with_unicode_path(self):
        """Dot-notation field path with non-ASCII segments resolves correctly."""
        rule = FinancialLimitRule(field="montant.valeur", max=100)

        verdict = await rule.evaluate({"montant": {"valeur": 500}})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_pii_custom_terms_unicode(self):
        """Chinese characters in custom terms are matched via case-insensitive search."""
        rule = PiiDetectionRule(custom_terms=["\u79d8\u5bc6"])
        verdict = await rule.evaluate({"body": "\u8fd9\u662f\u79d8\u5bc6"})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_pii_custom_terms_emoji(self):
        """Emoji custom terms are matched in payload text."""
        rule = PiiDetectionRule(custom_terms=["\U0001f4b0"])
        verdict = await rule.evaluate({"body": "Show me the \U0001f4b0"})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_rate_limit_key_field_unicode(self):
        """Unicode key_field resolves via resolve_field correctly."""
        rule = RateLimitRule(key_field="\u7528\u6237", max_actions=1, window_seconds=60)

        verdict = await rule.evaluate({"\u7528\u6237": "alice"})
        assert verdict.status == "approved"

        verdict = await rule.evaluate({"\u7528\u6237": "alice"})
        assert verdict.blocked

    def test_config_on_error_with_whitespace(self):
        """on_error with surrounding whitespace is not in the valid set."""
        with pytest.raises(CogniWallConfigError, match="Invalid on_error"):
            parse_config({"on_error": " block "})


# ---------------------------------------------------------------------------
# Config edge cases — parsing
# ---------------------------------------------------------------------------


class TestConfigEdgeCasesParsing:
    """Edge cases in rule config dicts: missing type, wrong types, extra keys."""

    def test_config_rule_with_no_type_key(self):
        """Rule dict without 'type' key: type resolves to None, rejected."""
        with pytest.raises(CogniWallConfigError, match="Unknown rule type"):
            parse_config({"rules": [{"block": ["ssn"]}]})

    def test_config_rule_with_type_none(self):
        """Explicit type=None: same error as missing type key."""
        with pytest.raises(CogniWallConfigError, match="Unknown rule type"):
            parse_config({"rules": [{"type": None}]})

    def test_config_rule_with_type_integer(self):
        """type=42: not in registry, raises CogniWallConfigError."""
        with pytest.raises(CogniWallConfigError, match="Unknown rule type"):
            parse_config({"rules": [{"type": 42}]})

    def test_config_rule_with_extra_unknown_keys(self):
        """Extra unrecognized keys in a rule config are silently ignored."""
        result = parse_config({
            "rules": [
                {"type": "pii_detection", "block": ["ssn"], "unknown": "value"},
            ]
        })
        assert len(result["rules"]) == 1
        assert isinstance(result["rules"][0], PiiDetectionRule)
