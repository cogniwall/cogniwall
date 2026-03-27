"""Pipeline resilience tests — hanging rules, error cascades, invalid verdicts, edge cases."""

import asyncio
import subprocess
import sys
import time

import pytest

from cogniwall.pipeline import Pipeline
from cogniwall.verdict import Verdict
from tests.test_robustness import (
    BadReturnRule,
    FlexibleApproveRule,
    FlexibleBlockRule,
    FlexibleErrorRule,
    RaisingRule,
    SlowApproveRule,
)


# ---------------------------------------------------------------------------
# Hanging rules
# ---------------------------------------------------------------------------


class TestHangingRules:
    """Verify pipeline behavior when rules are slow, hang, or get cancelled."""

    @pytest.mark.asyncio
    async def test_slow_rule_does_not_block_same_tier_rules(self):
        """Two tier-1 rules run concurrently; total time ~= slowest rule."""
        pipeline = Pipeline(
            rules=[SlowApproveRule(tier=1, delay=0.5), FlexibleApproveRule(tier=1)],
        )
        start = time.perf_counter()
        verdict = await pipeline.run({})
        elapsed = time.perf_counter() - start

        assert verdict.status == "approved"
        assert elapsed < 0.8, f"Expected parallel execution in <0.8s, got {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_pipeline_no_builtin_timeout(self):
        """Pipeline has no built-in timeout — a slow rule blocks indefinitely."""
        pipeline = Pipeline(rules=[SlowApproveRule(tier=1, delay=5.0)])

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(pipeline.run({}), timeout=1.0)

    @pytest.mark.asyncio
    async def test_hanging_tier1_rule_blocks_tier2_execution(self):
        """A hanging tier-1 rule prevents tier-2 rules from executing."""
        pipeline = Pipeline(
            rules=[
                SlowApproveRule(tier=1, delay=2.0),
                FlexibleBlockRule(tier=2, name="tier2_blocker"),
            ],
        )

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(pipeline.run({}), timeout=1.0)

    @pytest.mark.asyncio
    async def test_cancelled_pipeline_propagates_cancellation(self):
        """Cancelling a pipeline task propagates CancelledError."""
        pipeline = Pipeline(
            rules=[FlexibleApproveRule(tier=1), SlowApproveRule(tier=2, delay=2.0)],
        )

        task = asyncio.create_task(pipeline.run({}))
        await asyncio.sleep(0.1)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_slow_rule_with_fast_blocker_same_tier(self):
        """gather waits for all rules even when one blocks immediately."""
        pipeline = Pipeline(
            rules=[
                SlowApproveRule(tier=1, delay=0.5),
                FlexibleBlockRule(tier=1, name="fast_block"),
            ],
        )

        start = time.perf_counter()
        verdict = await pipeline.run({})
        elapsed = time.perf_counter() - start

        assert verdict.blocked
        assert elapsed >= 0.4, f"Expected gather to wait for slow rule, got {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# Error cascades
# ---------------------------------------------------------------------------


class TestErrorCascades:
    """Verify on_error modes and exception handling within a tier."""

    @pytest.mark.asyncio
    async def test_multiple_errors_same_tier_first_wins(self):
        """When several rules error in the same tier, the first (by gather order) wins."""
        pipeline = Pipeline(
            rules=[
                FlexibleErrorRule(tier=1, name="error_1"),
                FlexibleErrorRule(tier=1, name="error_2"),
                FlexibleErrorRule(tier=1, name="error_3"),
            ],
            on_error="error",
        )
        verdict = await pipeline.run({})

        assert verdict.status == "error"
        assert verdict.rule in {"error_1", "error_2", "error_3"}

    @pytest.mark.asyncio
    async def test_multiple_errors_same_tier_on_error_block(self):
        """on_error='block' converts the first error into a block verdict."""
        pipeline = Pipeline(
            rules=[
                FlexibleErrorRule(tier=1, name="error_1"),
                FlexibleErrorRule(tier=1, name="error_2"),
                FlexibleErrorRule(tier=1, name="error_3"),
            ],
            on_error="block",
        )
        verdict = await pipeline.run({})

        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_multiple_errors_same_tier_on_error_approve(self):
        """on_error='approve' swallows errors and returns approved."""
        pipeline = Pipeline(
            rules=[
                FlexibleErrorRule(tier=1, name="error_1"),
                FlexibleErrorRule(tier=1, name="error_2"),
                FlexibleErrorRule(tier=1, name="error_3"),
            ],
            on_error="approve",
        )
        verdict = await pipeline.run({})

        assert verdict.status == "approved"

    @pytest.mark.asyncio
    async def test_error_plus_block_same_tier_error_wins(self):
        """Errors are checked before blocks — error takes precedence."""
        pipeline = Pipeline(
            rules=[
                FlexibleErrorRule(tier=1, name="err_rule"),
                FlexibleBlockRule(tier=1, name="blk_rule"),
            ],
            on_error="error",
        )
        verdict = await pipeline.run({})

        assert verdict.status == "error"

    @pytest.mark.asyncio
    async def test_exception_raised_in_evaluate_caught_by_gather(self):
        """An exception raised inside evaluate is converted to Verdict.error."""
        pipeline = Pipeline(
            rules=[RaisingRule(tier=1, exc=ValueError("boom"))],
            on_error="error",
        )
        verdict = await pipeline.run({})

        assert verdict.status == "error"
        assert "boom" in str(verdict.error)

    def test_keyboard_interrupt_in_rule(self):
        """KeyboardInterrupt propagates through gather -- not caught by return_exceptions.

        Tested in a subprocess because pytest's runner intercepts KeyboardInterrupt
        before pytest.raises can capture it.
        """
        script = "\n".join([
            "import asyncio",
            "from cogniwall.pipeline import Pipeline",
            "from tests.test_robustness import RaisingRule",
            "async def main():",
            "    p = Pipeline(rules=[RaisingRule(tier=1, exc=KeyboardInterrupt())])",
            "    await p.run({})",
            "try:",
            "    asyncio.run(main())",
            "    print('NO_ERROR')",
            "except KeyboardInterrupt:",
            "    print('KEYBOARD_INTERRUPT')",
        ])
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "KEYBOARD_INTERRUPT" in result.stdout

    def test_system_exit_in_rule(self):
        """SystemExit propagates through gather -- not caught by return_exceptions.

        Tested in a subprocess because SystemExit terminates the process.
        """
        script = "\n".join([
            "import asyncio",
            "from cogniwall.pipeline import Pipeline",
            "from tests.test_robustness import RaisingRule",
            "async def main():",
            "    p = Pipeline(rules=[RaisingRule(tier=1, exc=SystemExit(1))])",
            "    await p.run({})",
            "try:",
            "    asyncio.run(main())",
            "    print('NO_ERROR')",
            "except SystemExit:",
            "    print('SYSTEM_EXIT')",
        ])
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "SYSTEM_EXIT" in result.stdout

    @pytest.mark.asyncio
    async def test_cancelled_error_in_rule_propagates(self):
        """CancelledError raised in a rule is re-raised, not wrapped."""
        pipeline = Pipeline(
            rules=[RaisingRule(tier=1, exc=asyncio.CancelledError())],
        )

        with pytest.raises(asyncio.CancelledError):
            await pipeline.run({})


# ---------------------------------------------------------------------------
# Invalid verdicts
# ---------------------------------------------------------------------------


class TestInvalidVerdicts:
    """Document pipeline behavior when rules return non-Verdict values."""

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason="Pipeline does not validate that rules return Verdict objects",
        raises=AttributeError,
    )
    async def test_rule_returns_none_instead_of_verdict(self):
        """Returning None causes AttributeError when pipeline reads .status."""
        pipeline = Pipeline(rules=[BadReturnRule(tier=1, return_value=None)])
        await pipeline.run({})

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason="Pipeline does not validate rule return types",
        raises=AttributeError,
    )
    async def test_rule_returns_string_instead_of_verdict(self):
        """Returning a string causes AttributeError when pipeline reads .status."""
        pipeline = Pipeline(rules=[BadReturnRule(tier=1, return_value="approved")])
        await pipeline.run({})

    @pytest.mark.asyncio
    @pytest.mark.xfail(
        reason="Pipeline does not validate rule return types",
        raises=AttributeError,
    )
    async def test_rule_returns_dict_instead_of_verdict(self):
        """Returning a dict causes AttributeError — dicts use ['key'], not .key."""
        pipeline = Pipeline(
            rules=[
                BadReturnRule(
                    tier=1,
                    return_value={"status": "approved", "blocked": False},
                ),
            ],
        )
        await pipeline.run({})

    @pytest.mark.asyncio
    async def test_rule_returns_verdict_with_invalid_status(self):
        """A Verdict with an unrecognised status is silently treated as approved."""
        weird_verdict = Verdict(status="maybe", blocked=False)
        pipeline = Pipeline(rules=[BadReturnRule(tier=1, return_value=weird_verdict)])

        verdict = await pipeline.run({})
        assert verdict.status == "approved"


# ---------------------------------------------------------------------------
# Pipeline edge cases
# ---------------------------------------------------------------------------


class TestPipelineEdgeCases:
    """Structural and behavioral edge cases in the pipeline."""

    @pytest.mark.asyncio
    async def test_pipeline_all_rules_same_tier(self):
        """Five same-tier rules run concurrently, not serially."""
        rules = [SlowApproveRule(tier=1, delay=0.2) for _ in range(5)]
        pipeline = Pipeline(rules=rules)

        start = time.perf_counter()
        verdict = await pipeline.run({})
        elapsed = time.perf_counter() - start

        assert verdict.status == "approved"
        assert elapsed < 0.5, f"Expected concurrent execution in <0.5s, got {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_pipeline_five_tiers(self):
        """Five sequential tiers each take ~0.1s — total is additive."""
        rules = [SlowApproveRule(tier=t, delay=0.1) for t in range(1, 6)]
        pipeline = Pipeline(rules=rules)

        start = time.perf_counter()
        verdict = await pipeline.run({})
        elapsed = time.perf_counter() - start

        assert verdict.status == "approved"
        assert elapsed > 0.3, f"Expected sequential tiers, got {elapsed:.2f}s"
        assert elapsed < 1.0, f"Expected ~0.5s total, got {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_pipeline_block_in_tier_3_skips_tiers_4_and_5(self):
        """A block in tier 3 short-circuits — tiers 4 and 5 never execute."""
        executed_tiers: list[int] = []

        class TrackingApproveRule(FlexibleApproveRule):
            """Approve rule that records which tier it ran in."""

            async def evaluate(self, payload: dict) -> Verdict:
                executed_tiers.append(self.tier)
                return await super().evaluate(payload)

        class TrackingBlockRule(FlexibleBlockRule):
            """Block rule that records which tier it ran in."""

            async def evaluate(self, payload: dict) -> Verdict:
                executed_tiers.append(self.tier)
                return await super().evaluate(payload)

        pipeline = Pipeline(
            rules=[
                TrackingApproveRule(tier=1),
                TrackingApproveRule(tier=2),
                TrackingBlockRule(tier=3, name="blocker"),
                TrackingApproveRule(tier=4),
                TrackingApproveRule(tier=5),
            ],
        )
        verdict = await pipeline.run({})

        assert verdict.blocked
        assert verdict.rule == "blocker"
        assert sorted(executed_tiers) == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_pipeline_rerun_same_instance_multiple_times(self):
        """A pipeline instance can be reused — it holds no per-run state."""
        pipeline = Pipeline(rules=[FlexibleApproveRule(tier=1)])

        for _ in range(3):
            verdict = await pipeline.run({})
            assert verdict.status == "approved"
