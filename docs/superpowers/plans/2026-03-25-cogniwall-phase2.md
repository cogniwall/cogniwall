# CogniWall Phase 2: Additional Guardrail Modules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add tone/sentiment veto, rate limiting, and custom rule support to the CogniWall library, plus extract shared utilities.

**Architecture:** Four independent changes that build on the existing Rule ABC pattern. Start with the shared utility refactor (unblocks other tasks), then implement the two new rules, then add custom rule integration tests. Config and exports updated last.

**Tech Stack:** Python 3.11+, pytest, pytest-asyncio, asyncio.Lock (rate limiting)

**Spec:** `docs/superpowers/specs/2026-03-25-cogniwall-phase2-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `cogniwall/rules/base.py` | Modify | Add `resolve_field` utility (moved from financial.py) |
| `cogniwall/rules/financial.py` | Modify | Import `resolve_field` from base instead of local `_resolve_field` |
| `cogniwall/rules/tone_sentiment.py` | Create | `ToneSentimentRule` — LLM-based tone analysis |
| `cogniwall/rules/rate_limit.py` | Create | `RateLimitRule` — in-memory rate limiting |
| `cogniwall/rules/__init__.py` | Modify | Add new rule exports |
| `cogniwall/__init__.py` | Modify | Add new rule exports |
| `cogniwall/config.py` | Modify | Register new rules, add validation |
| `tests/test_rules/test_tone_sentiment.py` | Create | Tone/sentiment rule tests |
| `tests/test_rules/test_rate_limit.py` | Create | Rate limit rule tests |
| `tests/test_custom_rules.py` | Create | Custom rule integration tests |
| `tests/test_config.py` | Modify | Add validation tests for new rule types |
| `cogniwall.yaml` | Modify | Add new rule examples |

---

### Task 1: Extract `resolve_field` to Shared Utility

**Files:**
- Modify: `cogniwall/rules/base.py`
- Modify: `cogniwall/rules/financial.py`

- [ ] **Step 1: Write the failing test**

`tests/test_rules/test_base.py` — add to existing file:
```python
from cogniwall.rules.base import resolve_field


class TestResolveField:
    def test_top_level_field(self):
        assert resolve_field({"amount": 100}, "amount") == 100

    def test_nested_field(self):
        assert resolve_field({"data": {"refund": {"amount": 50}}}, "data.refund.amount") == 50

    def test_missing_field(self):
        assert resolve_field({"other": 1}, "amount") is None

    def test_missing_nested_field(self):
        assert resolve_field({"data": {}}, "data.refund.amount") is None

    def test_non_dict_intermediate(self):
        assert resolve_field({"data": "string"}, "data.inner") is None

    def test_none_value(self):
        assert resolve_field({"amount": None}, "amount") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_rules/test_base.py::TestResolveField -v`
Expected: FAIL — `ImportError: cannot import name 'resolve_field'`

- [ ] **Step 3: Add `resolve_field` to `cogniwall/rules/base.py`**

Append after `_collect_strings`:
```python
def resolve_field(payload: dict, field_path: str) -> object:
    """Resolve a dot-notation field path in a nested dict.

    Returns None if any segment is missing or not a dict.
    Shared utility used by financial, tone/sentiment, and rate limit rules.
    """
    current = payload
    for segment in field_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
        if current is None:
            return None
    return current
```

- [ ] **Step 4: Update `cogniwall/rules/financial.py` to use shared utility**

Replace the import and remove the local `_resolve_field`:
```python
# Change line 3 from:
from cogniwall.rules.base import Rule
# To:
from cogniwall.rules.base import Rule, resolve_field
```

Replace `_resolve_field` call on line 22 with `resolve_field`:
```python
value = resolve_field(payload, self.field)
```

Delete the local `_resolve_field` function (lines 54-66).

- [ ] **Step 5: Run all tests to verify nothing broke**

Run: `.venv/bin/pytest -v`
Expected: all 91 existing tests + 6 new = 97 passed

- [ ] **Step 6: Commit**

```bash
git add cogniwall/rules/base.py cogniwall/rules/financial.py tests/test_rules/test_base.py
git commit -m "refactor: extract resolve_field to shared utility in rules/base.py"
```

---

### Task 2: Rate Limit Rule

**Files:**
- Create: `cogniwall/rules/rate_limit.py`
- Create: `tests/test_rules/test_rate_limit.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_rules/test_rate_limit.py`:
```python
import asyncio
import time

import pytest
from cogniwall.rules.rate_limit import RateLimitRule


class TestRateLimitRule:
    @pytest.mark.asyncio
    async def test_allows_within_limit(self):
        rule = RateLimitRule(max_actions=3, window_seconds=60)
        for _ in range(3):
            verdict = await rule.evaluate({"user_id": "user_1"})
            assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_blocks_over_limit(self):
        rule = RateLimitRule(max_actions=3, window_seconds=60)
        for _ in range(3):
            await rule.evaluate({"user_id": "user_1"})
        verdict = await rule.evaluate({"user_id": "user_1"})
        assert verdict.blocked
        assert verdict.rule == "rate_limit"
        assert verdict.details["count"] == 3
        assert verdict.details["max_actions"] == 3

    @pytest.mark.asyncio
    async def test_per_key_isolation(self):
        rule = RateLimitRule(max_actions=2, window_seconds=60, key_field="user_id")
        # Fill up user_a
        for _ in range(2):
            await rule.evaluate({"user_id": "user_a"})
        # user_a is blocked
        assert (await rule.evaluate({"user_id": "user_a"})).blocked
        # user_b is still allowed
        assert not (await rule.evaluate({"user_id": "user_b"})).blocked

    @pytest.mark.asyncio
    async def test_global_mode(self):
        rule = RateLimitRule(max_actions=2, window_seconds=60)
        await rule.evaluate({"data": "first"})
        await rule.evaluate({"data": "second"})
        verdict = await rule.evaluate({"data": "third"})
        assert verdict.blocked
        assert verdict.details["key"] == "__global__"

    @pytest.mark.asyncio
    async def test_window_expiry(self):
        rule = RateLimitRule(max_actions=2, window_seconds=0.1)
        await rule.evaluate({"data": "first"})
        await rule.evaluate({"data": "second"})
        # Wait for window to expire
        await asyncio.sleep(0.15)
        verdict = await rule.evaluate({"data": "third"})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_missing_key_field_approves(self):
        rule = RateLimitRule(max_actions=1, window_seconds=60, key_field="user_id")
        verdict = await rule.evaluate({"other": "data"})
        assert not verdict.blocked

    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        rule = RateLimitRule(max_actions=5, window_seconds=60)
        # Fire 10 concurrent evaluations
        verdicts = await asyncio.gather(
            *[rule.evaluate({"data": f"action_{i}"}) for i in range(10)]
        )
        approved = sum(1 for v in verdicts if not v.blocked)
        blocked = sum(1 for v in verdicts if v.blocked)
        assert approved == 5
        assert blocked == 5


class TestRateLimitFromConfig:
    def test_from_config(self):
        rule = RateLimitRule.from_config({
            "max_actions": 10,
            "window_seconds": 3600,
            "key_field": "agent_id",
        })
        assert isinstance(rule, RateLimitRule)

    def test_from_config_global(self):
        rule = RateLimitRule.from_config({
            "max_actions": 100,
            "window_seconds": 60,
        })
        assert isinstance(rule, RateLimitRule)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_rules/test_rate_limit.py -v`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Implement `RateLimitRule`**

`cogniwall/rules/rate_limit.py`:
```python
from __future__ import annotations

import asyncio
import time

from cogniwall.rules.base import Rule, resolve_field
from cogniwall.verdict import Verdict


class RateLimitRule(Rule):
    tier = 1
    rule_name = "rate_limit"

    def __init__(
        self,
        max_actions: int,
        window_seconds: float,
        key_field: str | None = None,
    ):
        self.max_actions = max_actions
        self.window_seconds = window_seconds
        self.key_field = key_field
        self._timestamps: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def evaluate(self, payload: dict) -> Verdict:
        # Resolve key
        if self.key_field:
            key = resolve_field(payload, self.key_field)
            if key is None:
                return Verdict.approved()
            key = str(key)
        else:
            key = "__global__"

        now = time.monotonic()
        cutoff = now - self.window_seconds

        async with self._lock:
            timestamps = self._timestamps.get(key, [])
            # Prune expired
            timestamps = [t for t in timestamps if t > cutoff]

            if len(timestamps) >= self.max_actions:
                self._timestamps[key] = timestamps
                return Verdict.blocked(
                    rule=self.rule_name,
                    reason=f"Rate limit exceeded: {self.max_actions} actions in {self.window_seconds}s for key '{key}'",
                    details={
                        "key": key,
                        "count": len(timestamps),
                        "max_actions": self.max_actions,
                        "window_seconds": self.window_seconds,
                    },
                )

            timestamps.append(now)
            self._timestamps[key] = timestamps
            return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> RateLimitRule:
        return cls(
            max_actions=config["max_actions"],
            window_seconds=config["window_seconds"],
            key_field=config.get("key_field"),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_rules/test_rate_limit.py -v`
Expected: all passed

- [ ] **Step 5: Run full suite**

Run: `.venv/bin/pytest -v`
Expected: all passed

- [ ] **Step 6: Commit**

```bash
git add cogniwall/rules/rate_limit.py tests/test_rules/test_rate_limit.py
git commit -m "feat: add rate limit rule with in-memory per-key tracking"
```

---

### Task 3: Tone/Sentiment Veto Rule

**Files:**
- Create: `cogniwall/rules/tone_sentiment.py`
- Create: `tests/test_rules/test_tone_sentiment.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_rules/test_tone_sentiment.py`:
```python
import pytest
from unittest.mock import AsyncMock, patch
from cogniwall.rules.tone_sentiment import ToneSentimentRule, VALID_PRESETS


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_rules/test_tone_sentiment.py -v`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Implement `ToneSentimentRule`**

`cogniwall/rules/tone_sentiment.py`:
```python
from __future__ import annotations

from cogniwall.rules.base import Rule, resolve_field
from cogniwall.verdict import Verdict

VALID_PRESETS = frozenset({"angry", "sarcastic", "apologetic", "threatening", "dismissive"})


class ToneSentimentRule(Rule):
    tier = 2
    rule_name = "tone_sentiment"

    def __init__(
        self,
        field: str,
        block: list[str] | None = None,
        custom: list[str] | None = None,
        provider: str = "anthropic",
        model: str = "claude-haiku-4-5-20251001",
        api_key: str | None = None,
        api_key_env: str | None = None,
    ):
        self.field = field
        self.block = block or []
        self.custom = custom or []
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.api_key_env = api_key_env

    async def evaluate(self, payload: dict) -> Verdict:
        value = resolve_field(payload, self.field)
        if value is None or not isinstance(value, str):
            return Verdict.approved()

        try:
            matched_tone = await self._call_llm(value)
            if matched_tone.upper() == "NONE":
                return Verdict.approved()
            return Verdict.blocked(
                rule=self.rule_name,
                reason=f"Tone detected: {matched_tone}",
                details={"tone": matched_tone, "field": self.field},
            )
        except Exception as exc:
            return Verdict.error(rule=self.rule_name, error=exc)

    async def _call_llm(self, text: str) -> str:
        """Call the LLM to classify text tone. Returns tone name or 'NONE'."""
        import os

        api_key = self.api_key
        if not api_key and self.api_key_env:
            api_key = os.environ.get(self.api_key_env)

        if not api_key:
            raise ValueError(
                f"No API key provided. Set api_key or api_key_env for {self.provider}."
            )

        all_tones = self.block + self.custom
        tone_list = ", ".join(f'"{t}"' for t in all_tones)

        prompt = (
            f"Analyze the tone of the following text. "
            f"Does it match any of these tones: {tone_list}?\n\n"
            f"Respond with ONLY the matched tone name (exactly as listed) "
            f"or 'NONE' if no match.\n\n"
            f"Text:\n{text}"
        )

        if self.provider == "anthropic":
            return await self._call_anthropic(api_key, prompt)
        elif self.provider == "openai":
            return await self._call_openai(api_key, prompt)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    async def _call_anthropic(self, api_key: str, prompt: str) -> str:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=self.model,
            max_tokens=50,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()

    async def _call_openai(self, api_key: str, prompt: str) -> str:
        import openai

        client = openai.AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model=self.model,
            max_tokens=50,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content.strip()

    @classmethod
    def from_config(cls, config: dict) -> ToneSentimentRule:
        return cls(
            field=config["field"],
            block=config.get("block", []),
            custom=config.get("custom", []),
            provider=config.get("provider", "anthropic"),
            model=config.get("model", "claude-haiku-4-5-20251001"),
            api_key_env=config.get("api_key_env"),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_rules/test_tone_sentiment.py -v`
Expected: all passed

- [ ] **Step 5: Run full suite**

Run: `.venv/bin/pytest -v`
Expected: all passed

- [ ] **Step 6: Commit**

```bash
git add cogniwall/rules/tone_sentiment.py tests/test_rules/test_tone_sentiment.py
git commit -m "feat: add tone/sentiment veto rule with preset and custom tones"
```

---

### Task 4: Custom Rules Integration Tests

**Files:**
- Create: `tests/test_custom_rules.py`

- [ ] **Step 1: Write the integration tests**

`tests/test_custom_rules.py`:
```python
import pytest
from cogniwall import CogniWall, Verdict
from cogniwall.rules.base import Rule, extract_strings, resolve_field
from cogniwall.rules.pii import PiiDetectionRule


class NoProfanityRule(Rule):
    """Example custom Tier 1 rule."""
    tier = 1
    rule_name = "no_profanity"
    BLOCKED_WORDS = {"damn", "hell"}

    async def evaluate(self, payload: dict) -> Verdict:
        texts = extract_strings(payload)
        for text in texts:
            for word in self.BLOCKED_WORDS:
                if word in text.lower():
                    return Verdict.blocked(
                        rule=self.rule_name,
                        reason=f"Profanity detected: {word}",
                    )
        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> "NoProfanityRule":
        return cls()


class CustomFieldCheckRule(Rule):
    """Example custom Tier 1 rule using resolve_field."""
    tier = 1
    rule_name = "custom_field_check"

    async def evaluate(self, payload: dict) -> Verdict:
        status = resolve_field(payload, "order.status")
        if status == "cancelled":
            return Verdict.blocked(
                rule=self.rule_name,
                reason="Cannot act on cancelled orders",
            )
        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> "CustomFieldCheckRule":
        return cls()


class CustomTier2Rule(Rule):
    """Example custom Tier 2 rule."""
    tier = 2
    rule_name = "custom_tier2"

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.blocked(rule=self.rule_name, reason="always blocks")

    @classmethod
    def from_config(cls, config: dict) -> "CustomTier2Rule":
        return cls()


class CustomErrorRule(Rule):
    """Custom rule that always errors."""
    tier = 1
    rule_name = "custom_error"

    async def evaluate(self, payload: dict) -> Verdict:
        return Verdict.error(rule=self.rule_name, error=RuntimeError("custom failure"))

    @classmethod
    def from_config(cls, config: dict) -> "CustomErrorRule":
        return cls()


class TestCustomRuleInPipeline:
    @pytest.mark.asyncio
    async def test_custom_tier1_alongside_builtin(self):
        guard = CogniWall(rules=[
            NoProfanityRule(),
            PiiDetectionRule(block=["ssn"]),
        ])
        # Custom rule blocks
        verdict = await guard.evaluate_async({"body": "damn it"})
        assert verdict.blocked
        assert verdict.rule == "no_profanity"

    @pytest.mark.asyncio
    async def test_custom_tier2_sorted_correctly(self):
        guard = CogniWall(rules=[
            CustomTier2Rule(),
            PiiDetectionRule(block=["ssn"]),
        ])
        # Tier 1 (PII) runs first, approves, then Tier 2 blocks
        verdict = await guard.evaluate_async({"body": "clean text"})
        assert verdict.blocked
        assert verdict.rule == "custom_tier2"

    @pytest.mark.asyncio
    async def test_custom_error_handled_by_on_error(self):
        guard = CogniWall(rules=[CustomErrorRule()], on_error="block")
        verdict = await guard.evaluate_async({"body": "hello"})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_custom_rule_uses_resolve_field(self):
        guard = CogniWall(rules=[CustomFieldCheckRule()])
        verdict = await guard.evaluate_async({"order": {"status": "cancelled"}})
        assert verdict.blocked
        assert verdict.rule == "custom_field_check"

    @pytest.mark.asyncio
    async def test_custom_rule_uses_extract_strings(self):
        guard = CogniWall(rules=[NoProfanityRule()])
        # Nested payload — extract_strings should find it
        verdict = await guard.evaluate_async({"nested": {"text": "go to hell"}})
        assert verdict.blocked

    @pytest.mark.asyncio
    async def test_mixed_builtin_and_custom(self):
        guard = CogniWall(rules=[
            PiiDetectionRule(block=["ssn"]),
            NoProfanityRule(),
            CustomFieldCheckRule(),
        ])
        # Clean payload passes all rules
        verdict = await guard.evaluate_async({"body": "Hello", "order": {"status": "active"}})
        assert not verdict.blocked
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_custom_rules.py -v`
Expected: all passed (these use existing infrastructure)

- [ ] **Step 3: Run full suite**

Run: `.venv/bin/pytest -v`
Expected: all passed

- [ ] **Step 4: Commit**

```bash
git add tests/test_custom_rules.py
git commit -m "feat: add custom rule integration tests with extract_strings and resolve_field"
```

---

### Task 5: Config Integration & Exports

**Files:**
- Modify: `cogniwall/config.py`
- Modify: `cogniwall/rules/__init__.py`
- Modify: `cogniwall/__init__.py`
- Modify: `tests/test_config.py`
- Modify: `cogniwall.yaml`

- [ ] **Step 1: Write the failing config validation tests**

Add to `tests/test_config.py`:
```python
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
            "rules": [{"type": "tone_sentiment", "field": "body", "block": ["angry"], "custom": ["legally liable"]}],
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_config.py::TestToneSentimentValidation tests/test_config.py::TestRateLimitValidation -v`
Expected: FAIL — unknown rule type

- [ ] **Step 3: Update `cogniwall/config.py`**

Add imports at top:
```python
from cogniwall.rules.tone_sentiment import ToneSentimentRule, VALID_PRESETS
from cogniwall.rules.rate_limit import RateLimitRule
```

Add to `_RULE_REGISTRY`:
```python
_RULE_REGISTRY: dict[str, type[Rule]] = {
    "pii_detection": PiiDetectionRule,
    "financial_limit": FinancialLimitRule,
    "prompt_injection": PromptInjectionRule,
    "tone_sentiment": ToneSentimentRule,
    "rate_limit": RateLimitRule,
}
```

Add validation cases in `_validate_rule_config`:
```python
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
        if "window_seconds" not in config:
            raise CogniWallConfigError(
                "rate_limit rule requires 'window_seconds' parameter"
            )
        if config["window_seconds"] <= 0:
            raise CogniWallConfigError(
                f"rate_limit 'window_seconds' must be positive, got {config['window_seconds']}"
            )
```

- [ ] **Step 4: Update `cogniwall/rules/__init__.py`**

```python
"""Guardrail rule implementations."""

from cogniwall.rules.base import Rule
from cogniwall.rules.financial import FinancialLimitRule
from cogniwall.rules.pii import PiiDetectionRule
from cogniwall.rules.prompt_injection import PromptInjectionRule
from cogniwall.rules.rate_limit import RateLimitRule
from cogniwall.rules.tone_sentiment import ToneSentimentRule

__all__ = [
    "Rule",
    "PiiDetectionRule",
    "FinancialLimitRule",
    "PromptInjectionRule",
    "ToneSentimentRule",
    "RateLimitRule",
]
```

- [ ] **Step 5: Update `cogniwall/__init__.py`**

```python
"""CogniWall — a programmable firewall for autonomous AI agents."""

from cogniwall.guard import CogniWall
from cogniwall.verdict import Verdict
from cogniwall.rules.pii import PiiDetectionRule
from cogniwall.rules.financial import FinancialLimitRule
from cogniwall.rules.prompt_injection import PromptInjectionRule
from cogniwall.rules.tone_sentiment import ToneSentimentRule
from cogniwall.rules.rate_limit import RateLimitRule

__all__ = [
    "CogniWall",
    "Verdict",
    "PiiDetectionRule",
    "FinancialLimitRule",
    "PromptInjectionRule",
    "ToneSentimentRule",
    "RateLimitRule",
]
```

- [ ] **Step 6: Update `cogniwall.yaml` with new rule examples**

Add after the financial_limit rule section:
```yaml

  # Block unwanted tone in AI-generated content
  # Requires: pip install cogniwall[anthropic] or cogniwall[openai]
  # - type: tone_sentiment
  #   field: body
  #   block: [angry, sarcastic, apologetic]
  #   custom: ["sounds legally liable"]
  #   provider: anthropic
  #   model: claude-haiku-4-5-20251001
  #   api_key_env: ANTHROPIC_API_KEY

  # Rate limit actions per user/agent
  # - type: rate_limit
  #   max_actions: 5
  #   window_seconds: 3600
  #   key_field: user_id
```

- [ ] **Step 7: Run all tests**

Run: `.venv/bin/pytest -v`
Expected: all passed

- [ ] **Step 8: Commit**

```bash
git add cogniwall/config.py cogniwall/rules/__init__.py cogniwall/__init__.py cogniwall.yaml tests/test_config.py
git commit -m "feat: register tone_sentiment and rate_limit in config, update exports"
```

---

### Task 6: Full Test Suite Verification

- [ ] **Step 1: Run the complete test suite**

Run: `.venv/bin/pytest -v --tb=short`
Expected: all tests pass, no warnings

- [ ] **Step 2: Verify imports work from public API**

Run: `.venv/bin/python -c "from cogniwall import CogniWall, Verdict, PiiDetectionRule, FinancialLimitRule, PromptInjectionRule, ToneSentimentRule, RateLimitRule; print('All imports OK')"`
Expected: `All imports OK`

- [ ] **Step 3: Verify utility imports work**

Run: `.venv/bin/python -c "from cogniwall.rules.base import Rule, extract_strings, resolve_field; print('Utilities OK')"`
Expected: `Utilities OK`
