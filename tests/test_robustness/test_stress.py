"""Stress tests for CogniWall pipeline, rules, and internal utilities.

Covers large payloads, deep nesting, many rules, high throughput,
and _safe_copy edge cases.
"""

import asyncio
import time

import pytest

from cogniwall import CogniWall, FinancialLimitRule, PiiDetectionRule, RateLimitRule
from cogniwall.pipeline import Pipeline, _safe_copy
from cogniwall.rules.base import extract_strings
from cogniwall.verdict import Verdict
from tests.test_robustness import FlexibleApproveRule, FlexibleBlockRule, FlexibleErrorRule


# ---------------------------------------------------------------------------
# Large Payloads
# ---------------------------------------------------------------------------


class TestLargePayloads:
    @pytest.mark.asyncio
    async def test_payload_10k_flat_fields(self):
        """Dict with 10,000 top-level string fields must approve."""
        payload = {f"field_{i}": f"value_{i}" for i in range(10_000)}
        rule = PiiDetectionRule(block=["ssn"])
        verdict = await rule.evaluate(payload)
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_payload_10k_fields_with_ssn_in_last(self):
        """SSN hidden in the last of 10,000 fields must be caught."""
        payload = {f"field_{i}": f"value_{i}" for i in range(10_000)}
        payload["field_9999"] = "SSN: 123-45-6789"
        rule = PiiDetectionRule(block=["ssn"])
        verdict = await rule.evaluate(payload)
        assert verdict.blocked
        assert verdict.rule == "pii_detection"

    @pytest.mark.asyncio
    async def test_payload_large_string_value_1mb(self):
        """1 MB string payload must approve within 5 seconds."""
        payload = {"body": "a" * 1_000_000}
        rule = PiiDetectionRule(block=["ssn"])
        start = time.perf_counter()
        verdict = await rule.evaluate(payload)
        elapsed = time.perf_counter() - start
        assert verdict.status == "approved"
        assert elapsed < 5.0, f"Took {elapsed:.2f}s, expected < 5s"

    @pytest.mark.asyncio
    async def test_payload_large_string_with_ssn_at_end(self):
        """SSN appended to a 1 MB string must be detected."""
        payload = {"body": "x" * 1_000_000 + " 123-45-6789"}
        rule = PiiDetectionRule(block=["ssn"])
        verdict = await rule.evaluate(payload)
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_payload_10k_list_items(self):
        """List with 10,000 items must approve cleanly."""
        payload = {"items": [f"item_{i}" for i in range(10_000)]}
        rule = PiiDetectionRule(block=["ssn"])
        verdict = await rule.evaluate(payload)
        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_payload_mixed_types_10k(self):
        """10,000 mixed-type fields through PII + financial rules must complete."""
        payload = {}
        for i in range(10_000):
            remainder = i % 6
            if remainder == 0:
                payload[f"field_{i}"] = f"string_{i}"
            elif remainder == 1:
                payload[f"field_{i}"] = i
            elif remainder == 2:
                payload[f"field_{i}"] = float(i) + 0.5
            elif remainder == 3:
                payload[f"field_{i}"] = i % 2 == 0
            elif remainder == 4:
                payload[f"field_{i}"] = None
            elif remainder == 5:
                payload[f"field_{i}"] = [f"nested_{i}"]

        wall = CogniWall(
            rules=[
                PiiDetectionRule(block=["ssn"]),
                FinancialLimitRule(field="amount", max=100),
            ],
        )
        verdict = await wall.evaluate_async(payload)
        # No "amount" key, so financial approves; no SSNs, so PII approves
        assert verdict.status == "approved"


# ---------------------------------------------------------------------------
# Deep Nesting
# ---------------------------------------------------------------------------


class TestDeepNesting:
    @staticmethod
    def _build_nested(depth: int, leaf: dict | None = None) -> dict:
        """Build a dict nested to *depth* levels with an optional leaf."""
        d = leaf if leaf is not None else {"text": "hello"}
        for _ in range(depth):
            d = {"nested": d}
        return d

    @pytest.mark.asyncio
    async def test_safe_copy_nesting_depth_100(self):
        """100-level nesting should be handled without issue."""
        payload = self._build_nested(100)
        wall = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = await wall.evaluate_async(payload)
        assert verdict.status == "approved"

    @pytest.mark.xfail(
        reason="_safe_copy has no depth limit, may hit RecursionError at ~500 levels",
        raises=RecursionError,
    )
    @pytest.mark.asyncio
    async def test_safe_copy_nesting_depth_500(self):
        """500-level nesting may overflow _safe_copy's recursion."""
        payload = self._build_nested(500)
        wall = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = await wall.evaluate_async(payload)
        assert verdict.status == "approved"

    @pytest.mark.xfail(
        reason="_safe_copy hits RecursionError near Python default recursion limit",
        raises=RecursionError,
    )
    @pytest.mark.asyncio
    async def test_safe_copy_nesting_depth_990(self):
        """990-level nesting is very close to Python's default limit."""
        payload = self._build_nested(990)
        wall = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = await wall.evaluate_async(payload)
        assert verdict.status == "approved"

    @pytest.mark.xfail(
        reason="_safe_copy has no cycle detection, circular reference causes RecursionError",
        raises=RecursionError,
    )
    @pytest.mark.asyncio
    async def test_safe_copy_circular_reference(self):
        """Circular reference should cause RecursionError in _safe_copy."""
        d: dict = {}
        d["self"] = d
        wall = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        await wall.evaluate_async(d)

    def test_extract_strings_near_max_depth_1999(self):
        """extract_strings with 1999-level nesting should find the leaf string."""
        payload = self._build_nested(1999, leaf={"text": "hello"})
        strings = extract_strings(payload)
        assert "hello" in strings

    def test_extract_strings_at_max_depth_2000(self):
        """extract_strings at exactly 2000 nesting: SSN at depth 2001 is beyond _MAX_DEPTH."""
        payload = self._build_nested(2000, leaf={"text": "123-45-6789"})
        strings = extract_strings(payload)
        # The SSN sits at depth 2001 (2000 levels of nesting + 1 for the value),
        # which exceeds _MAX_DEPTH=2000, so it should NOT be extracted.
        assert "123-45-6789" not in strings

    def test_extract_strings_beyond_max_depth_2001(self):
        """extract_strings at 2001 nesting: must not crash, must not find SSN."""
        payload = self._build_nested(2001, leaf={"text": "123-45-6789"})
        strings = extract_strings(payload)
        assert "123-45-6789" not in strings


# ---------------------------------------------------------------------------
# Many Rules
# ---------------------------------------------------------------------------


class TestManyRules:
    @pytest.mark.asyncio
    async def test_pipeline_100_tier1_rules_all_approve(self):
        """100 tier-1 approve rules must complete within 2 seconds."""
        rules = [FlexibleApproveRule(tier=1) for _ in range(100)]
        pipeline = Pipeline(rules=rules)
        start = time.perf_counter()
        verdict = await pipeline.run({})
        elapsed = time.perf_counter() - start
        assert verdict.status == "approved"
        assert elapsed < 2.0, f"Took {elapsed:.2f}s, expected < 2s"

    @pytest.mark.asyncio
    async def test_pipeline_50_tier1_and_50_tier2_rules(self):
        """50 tier-1 + 50 tier-2 approve rules must complete within 2 seconds."""
        rules = [FlexibleApproveRule(tier=1) for _ in range(50)]
        rules += [FlexibleApproveRule(tier=2) for _ in range(50)]
        pipeline = Pipeline(rules=rules)
        start = time.perf_counter()
        verdict = await pipeline.run({})
        elapsed = time.perf_counter() - start
        assert verdict.status == "approved"
        assert elapsed < 2.0, f"Took {elapsed:.2f}s, expected < 2s"

    @pytest.mark.asyncio
    async def test_pipeline_100_rules_one_blocks(self):
        """99 approve + 1 block rule: pipeline must return blocked."""
        rules = [FlexibleApproveRule(tier=1) for _ in range(99)]
        rules.append(FlexibleBlockRule(tier=1, name="the_blocker"))
        pipeline = Pipeline(rules=rules)
        verdict = await pipeline.run({})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_pipeline_100_rules_one_errors(self):
        """99 approve + 1 error rule: pipeline must return error verdict."""
        rules = [FlexibleApproveRule(tier=1) for _ in range(99)]
        rules.append(FlexibleErrorRule(tier=1, name="the_error_rule", message="boom"))
        pipeline = Pipeline(rules=rules)
        verdict = await pipeline.run({})
        assert verdict.status == "error"


# ---------------------------------------------------------------------------
# High Throughput
# ---------------------------------------------------------------------------


class TestHighThroughput:
    @pytest.mark.asyncio
    async def test_1000_sequential_evaluations(self):
        """1000 sequential evaluations of clean payloads must all approve within 10s."""
        wall = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        start = time.perf_counter()
        for i in range(1_000):
            verdict = await wall.evaluate_async({"msg": f"hello {i}"})
            assert verdict.status == "approved"
        elapsed = time.perf_counter() - start
        assert elapsed < 10.0, f"Took {elapsed:.2f}s, expected < 10s"

    @pytest.mark.asyncio
    async def test_1000_sequential_evaluations_with_rate_limit(self):
        """Rate limit at 500/60s: first 500 approved, next 500 blocked."""
        rule = RateLimitRule(max_actions=500, window_seconds=60)
        wall = CogniWall(rules=[rule])
        approved_count = 0
        blocked_count = 0
        for i in range(1_000):
            verdict = await wall.evaluate_async({"action": f"do_{i}"})
            if verdict.status == "approved":
                approved_count += 1
            elif verdict.blocked:
                blocked_count += 1
        assert approved_count == 500
        assert blocked_count == 500

    @pytest.mark.asyncio
    async def test_rate_limit_memory_cleanup_after_window_expiry(self):
        """After window expires, old timestamps are cleaned and new evals succeed."""
        rule = RateLimitRule(max_actions=100, window_seconds=0.05)
        wall = CogniWall(rules=[rule])

        # Fill up the window
        for i in range(100):
            verdict = await wall.evaluate_async({"n": i})
            assert verdict.status == "approved"

        # Wait for the window to expire
        await asyncio.sleep(0.1)

        # Next evaluation should succeed and clean old timestamps
        verdict = await wall.evaluate_async({"n": "after_expiry"})
        assert verdict.status == "approved"
        assert len(rule._timestamps["__global__"]) == 1


# ---------------------------------------------------------------------------
# _safe_copy Edge Cases
# ---------------------------------------------------------------------------


class TestSafeCopyEdgeCases:
    def test_safe_copy_preserves_all_json_types(self):
        """_safe_copy must faithfully reproduce all JSON-serializable types."""
        payload = {
            "string": "hello",
            "integer": 42,
            "float": 3.14,
            "bool_true": True,
            "bool_false": False,
            "null": None,
            "list": [1, "two", 3.0],
            "dict": {"a": 1, "b": "two"},
        }
        result = _safe_copy(payload)
        assert result == payload
        # Verify it is actually a copy, not the same object
        assert result is not payload

    def test_safe_copy_converts_set_to_string(self):
        """Sets are not JSON-serializable; _safe_copy converts them to str."""
        payload = {"tags": {"a", "b"}}
        result = _safe_copy(payload)
        # The set is converted to its string representation
        assert isinstance(result["tags"], str)
        assert result["tags"] == str({"a", "b"})

    def test_safe_copy_converts_custom_object_to_string(self):
        """Custom objects are str()-ified; __reduce__ must NOT be called."""
        reduce_called = False

        class Sneaky:
            def __str__(self):
                return "sneaky_str"

            def __reduce__(self):
                nonlocal reduce_called
                reduce_called = True
                return (str, ("hacked",))

        instance = Sneaky()
        result = _safe_copy({"obj": instance})
        assert result == {"obj": "sneaky_str"}
        assert not reduce_called, "__reduce__ should never be invoked by _safe_copy"

    def test_safe_copy_tuple_preserved_as_tuple(self):
        """Tuples should be preserved as tuples, not converted to lists."""
        result = _safe_copy({"t": (1, 2, 3)})
        assert result["t"] == (1, 2, 3)
        assert isinstance(result["t"], tuple)

    def test_safe_copy_large_dict_no_mutation(self):
        """Modifying a _safe_copy result must not affect the original."""
        original = {f"key_{i}": f"val_{i}" for i in range(10_000)}
        copy = _safe_copy(original)

        # Mutate the copy
        copy["key_0"] = "MUTATED"
        copy["new_key"] = "new_value"

        # Original must be unchanged
        assert original["key_0"] == "val_0"
        assert "new_key" not in original
        assert len(original) == 10_000
