"""Tests for concurrent access patterns in CogniWall.

Verifies thread safety, async concurrency, rate-limit state integrity,
payload isolation, and audit path resilience under concurrent load.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cogniwall import CogniWall, PiiDetectionRule, PromptInjectionRule, RateLimitRule, Verdict
from cogniwall.audit import AuditClient
from cogniwall.rules.llm_provider import LLMProvider
from tests.test_robustness import FlexibleApproveRule, FlexibleBlockRule, FlexibleErrorRule


class _MockProvider(LLMProvider):
    provider_name = "mock"

    async def call(self, prompt, model, max_tokens=10):
        raise RuntimeError("Mock provider should not be called directly")

    @classmethod
    def from_config(cls, config):
        return cls()


# ---------------------------------------------------------------------------
# TestConcurrentEvaluateAsync
# ---------------------------------------------------------------------------


class TestConcurrentEvaluateAsync:
    """Concurrent evaluate_async calls on a shared CogniWall guard."""

    @pytest.mark.asyncio
    async def test_100_concurrent_evaluate_async_all_approve(self):
        """Fire 100 evaluate_async on same guard with PiiDetectionRule, clean payloads. All approved."""
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        payload = {"message": "Hello, this is a clean message."}

        results = await asyncio.gather(
            *[guard.evaluate_async(payload) for _ in range(100)]
        )

        assert len(results) == 100
        for v in results:
            assert v.status == "approved"
            assert v.blocked is False

    @pytest.mark.asyncio
    async def test_100_concurrent_evaluate_async_mixed_verdicts(self):
        """50 payloads with SSN, 50 clean. Exactly 50 blocked, 50 approved."""
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        ssn_payload = {"message": "My SSN is 123-45-6789"}
        clean_payload = {"message": "Nothing sensitive here"}

        coros = []
        for i in range(100):
            if i < 50:
                coros.append(guard.evaluate_async(ssn_payload))
            else:
                coros.append(guard.evaluate_async(clean_payload))

        results = await asyncio.gather(*coros)

        approved = [v for v in results if v.status == "approved"]
        blocked = [v for v in results if v.blocked]
        assert len(approved) == 50
        assert len(blocked) == 50

    @pytest.mark.asyncio
    async def test_concurrent_evaluate_async_with_multi_tier_pipeline(self):
        """PiiDetectionRule (tier 1) + mocked PromptInjectionRule (tier 2). 50 concurrent, all clean, all approved."""
        pii_rule = PiiDetectionRule(block=["ssn"])
        injection_rule = PromptInjectionRule(provider=_MockProvider(), model="test")

        guard = CogniWall(rules=[pii_rule, injection_rule])
        payload = {"message": "A perfectly normal request about weather."}

        with patch.object(
            PromptInjectionRule, "_call_llm", new_callable=AsyncMock, return_value=False
        ):
            results = await asyncio.gather(
                *[guard.evaluate_async(payload) for _ in range(50)]
            )

        assert len(results) == 50
        for v in results:
            assert v.status == "approved"
            assert v.blocked is False

    @pytest.mark.asyncio
    async def test_concurrent_evaluate_async_payload_isolation(self):
        """20 concurrent evaluations with unique payloads. All approved, no crashes."""
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])

        payloads = [{"id": i, "message": f"Clean message number {i}"} for i in range(20)]

        results = await asyncio.gather(
            *[guard.evaluate_async(p) for p in payloads]
        )

        assert len(results) == 20
        for v in results:
            assert v.status == "approved"
            assert v.blocked is False

    @pytest.mark.asyncio
    async def test_concurrent_evaluate_async_with_error_rule(self):
        """FlexibleErrorRule + on_error='block'. 50 concurrent calls. All must return blocked."""
        guard = CogniWall(
            rules=[FlexibleErrorRule(tier=1, name="err_rule", message="boom")],
            on_error="block",
        )
        payload = {"message": "anything"}

        results = await asyncio.gather(
            *[guard.evaluate_async(payload) for _ in range(50)]
        )

        assert len(results) == 50
        for v in results:
            assert v.blocked is True
            assert v.status == "blocked"


# ---------------------------------------------------------------------------
# TestConcurrentRateLimitState
# ---------------------------------------------------------------------------


class TestConcurrentRateLimitState:
    """Verify rate-limit state integrity under concurrent access."""

    @pytest.mark.asyncio
    async def test_rate_limit_500_concurrent_coroutines_exact_count(self):
        """RateLimitRule(max_actions=50, window=60s). 500 coroutines. Exactly 50 approved, 450 blocked."""
        rule = RateLimitRule(max_actions=50, window_seconds=60)
        guard = CogniWall(rules=[rule])
        payload = {"message": "ping"}

        results = await asyncio.gather(
            *[guard.evaluate_async(payload) for _ in range(500)]
        )

        approved = [v for v in results if v.status == "approved"]
        blocked = [v for v in results if v.blocked]
        assert len(approved) == 50
        assert len(blocked) == 450

    @pytest.mark.asyncio
    async def test_rate_limit_concurrent_per_key_isolation(self):
        """Per-key rate limit: 10 requests x 20 users. Each user: exactly 3 approved, 7 blocked."""
        rule = RateLimitRule(key_field="user_id", max_actions=3, window_seconds=60)
        guard = CogniWall(rules=[rule])

        coros = []
        for user_id in range(20):
            for _ in range(10):
                coros.append(guard.evaluate_async({"user_id": str(user_id), "message": "hi"}))

        results = await asyncio.gather(*coros)

        # Group results by user_id (order is preserved from coros construction)
        per_user: dict[int, list[Verdict]] = {}
        idx = 0
        for user_id in range(20):
            per_user[user_id] = results[idx : idx + 10]
            idx += 10

        for user_id, verdicts in per_user.items():
            user_approved = [v for v in verdicts if v.status == "approved"]
            user_blocked = [v for v in verdicts if v.blocked]
            assert len(user_approved) == 3, f"User {user_id}: expected 3 approved, got {len(user_approved)}"
            assert len(user_blocked) == 7, f"User {user_id}: expected 7 blocked, got {len(user_blocked)}"

    @pytest.mark.asyncio
    async def test_rate_limit_concurrent_window_expiry_during_burst(self):
        """Fill window with 5 requests, sleep past window, burst 100 concurrent. Exactly 5 of second burst approved."""
        rule = RateLimitRule(max_actions=5, window_seconds=0.1)
        guard = CogniWall(rules=[rule])
        payload = {"message": "ping"}

        # Fill the window
        first_batch = await asyncio.gather(
            *[guard.evaluate_async(payload) for _ in range(5)]
        )
        assert all(v.status == "approved" for v in first_batch)

        # Wait for window to expire
        await asyncio.sleep(0.15)

        # Burst 100 concurrent
        second_batch = await asyncio.gather(
            *[guard.evaluate_async(payload) for _ in range(100)]
        )
        approved = [v for v in second_batch if v.status == "approved"]
        blocked = [v for v in second_batch if v.blocked]
        assert len(approved) == 5
        assert len(blocked) == 95

    @pytest.mark.asyncio
    async def test_rate_limit_concurrent_with_rapid_key_creation(self):
        """1000 concurrent requests, each unique user_id. All approved. State has 1000 keys."""
        rule = RateLimitRule(key_field="user_id", max_actions=1, window_seconds=60)
        guard = CogniWall(rules=[rule])

        results = await asyncio.gather(
            *[guard.evaluate_async({"user_id": f"user_{i}"}) for i in range(1000)]
        )

        assert all(v.status == "approved" for v in results)
        assert len(rule._timestamps) == 1000

    @pytest.mark.asyncio
    async def test_rate_limit_shared_instance_across_multiple_guards(self):
        """One RateLimitRule shared by two guards. Total of 5 approved across both, 5 blocked."""
        rule = RateLimitRule(max_actions=5, window_seconds=60)
        guard_a = CogniWall(rules=[rule])
        guard_b = CogniWall(rules=[rule])
        payload = {"message": "ping"}

        # Fire 5 through guard A sequentially
        results_a = []
        for _ in range(5):
            v = await guard_a.evaluate_async(payload)
            results_a.append(v)

        # Fire 5 through guard B sequentially
        results_b = []
        for _ in range(5):
            v = await guard_b.evaluate_async(payload)
            results_b.append(v)

        all_results = results_a + results_b
        approved = [v for v in all_results if v.status == "approved"]
        blocked = [v for v in all_results if v.blocked]
        assert len(approved) == 5
        assert len(blocked) == 5


# ---------------------------------------------------------------------------
# TestConcurrentSyncEvaluate
# ---------------------------------------------------------------------------


class TestConcurrentSyncEvaluate:
    """Verify sync evaluate() works correctly from multiple threads."""

    def test_sync_evaluate_from_10_threads_with_pii_rule(self):
        """PiiDetectionRule, ThreadPoolExecutor(10), 50 sync evaluate calls. All approved."""
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        payload = {"message": "No sensitive data here"}

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(guard.evaluate, payload) for _ in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 50
        for v in results:
            assert v.status == "approved"
            assert v.blocked is False

    @pytest.mark.xfail(
        reason="asyncio.Lock does not protect across threads (each thread has own event loop)",
        strict=False,
    )
    def test_sync_evaluate_rate_limit_cross_thread_integrity(self):
        """RateLimitRule(max_actions=5) from 8 threads, 40 calls. Exactly 5 approved if lock works cross-thread."""
        rule = RateLimitRule(max_actions=5, window_seconds=60)
        guard = CogniWall(rules=[rule])
        payload = {"message": "ping"}

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(guard.evaluate, payload) for _ in range(40)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        approved = [v for v in results if v.status == "approved"]
        blocked = [v for v in results if v.blocked]
        # asyncio.Lock only protects within a single event loop. Each thread
        # creates its own loop via asyncio.run(), so the lock cannot serialize
        # access across threads. We assert exactly 5 approved, which will
        # likely fail (more than 5 approved) -- hence xfail.
        assert len(approved) == 5
        assert len(blocked) == 35

    @pytest.mark.asyncio
    async def test_sync_evaluate_from_running_event_loop(self):
        """Within an async test, call sync evaluate(). Verify it works (ThreadPoolExecutor path)."""
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        payload = {"message": "Clean payload, no PII"}

        # sync evaluate() detects a running loop and uses ThreadPoolExecutor
        verdict = guard.evaluate(payload)

        assert verdict.status == "approved"
        assert verdict.blocked is False


# ---------------------------------------------------------------------------
# TestConcurrentAuditPath
# ---------------------------------------------------------------------------


class TestConcurrentAuditPath:
    """Verify audit path resilience under concurrent evaluation."""

    @pytest.mark.asyncio
    async def test_concurrent_evaluate_with_audit_does_not_lose_events(self):
        """Mock AuditClient, 100 concurrent evaluate_async. audit.record called exactly 100 times."""
        audit = MagicMock(spec=AuditClient)
        audit.include_payload = False
        audit.flush_mode = "async"
        audit.build_event = MagicMock(return_value={"event_id": "test", "status": "approved"})
        audit.record = MagicMock()
        audit.start = AsyncMock()

        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            audit=audit,
        )
        payload = {"message": "Clean message"}

        results = await asyncio.gather(
            *[guard.evaluate_async(payload) for _ in range(100)]
        )

        assert len(results) == 100
        assert all(v.status == "approved" for v in results)
        assert audit.record.call_count == 100
        assert audit.build_event.call_count == 100

    @pytest.mark.asyncio
    async def test_concurrent_evaluate_with_audit_mixed_verdicts_all_recorded(self):
        """Mock AuditClient, 50 blocked + 50 approved concurrently. All 100 events recorded with correct status."""
        recorded_events: list[dict] = []

        def capture_record(event):
            recorded_events.append(event)

        audit = MagicMock(spec=AuditClient)
        audit.include_payload = False
        audit.flush_mode = "async"
        audit.build_event = MagicMock(
            side_effect=lambda verdict, payload=None, metadata=None: {
                "event_id": "test",
                "status": verdict.status,
            }
        )
        audit.record = MagicMock(side_effect=capture_record)
        audit.start = AsyncMock()

        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            audit=audit,
        )

        ssn_payload = {"message": "SSN: 123-45-6789"}
        clean_payload = {"message": "No PII here"}

        coros = []
        for i in range(100):
            if i < 50:
                coros.append(guard.evaluate_async(ssn_payload))
            else:
                coros.append(guard.evaluate_async(clean_payload))

        results = await asyncio.gather(*coros)

        assert len(results) == 100
        assert audit.record.call_count == 100

        recorded_approved = [e for e in recorded_events if e["status"] == "approved"]
        recorded_blocked = [e for e in recorded_events if e["status"] == "blocked"]
        assert len(recorded_approved) == 50
        assert len(recorded_blocked) == 50

    @pytest.mark.asyncio
    async def test_concurrent_evaluate_audit_exception_does_not_block(self):
        """Mock AuditClient whose build_event raises on every other call. 50 evaluations still return correct verdicts."""
        call_count = {"n": 0}

        def flaky_build_event(verdict, payload=None, metadata=None):
            call_count["n"] += 1
            if call_count["n"] % 2 == 0:
                raise RuntimeError("audit build_event failure")
            return {"event_id": "test", "status": verdict.status}

        audit = MagicMock(spec=AuditClient)
        audit.include_payload = False
        audit.flush_mode = "async"
        audit.build_event = MagicMock(side_effect=flaky_build_event)
        audit.record = MagicMock()
        audit.start = AsyncMock()

        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            audit=audit,
        )
        payload = {"message": "Nothing sensitive"}

        results = await asyncio.gather(
            *[guard.evaluate_async(payload) for _ in range(50)]
        )

        assert len(results) == 50
        for v in results:
            assert v.status == "approved"
            assert v.blocked is False
