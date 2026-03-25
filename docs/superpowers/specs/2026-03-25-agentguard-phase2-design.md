# AgentGuard Phase 2: Additional Guardrail Modules — Design Spec

## Overview

Phase 2 adds three new guardrail modules to the AgentGuard library and formalizes the custom rule extension API. All modules follow the existing `Rule` ABC pattern established in Phase 1.

This spec covers:
1. Tone/Sentiment Veto rule (LLM-based, Tier 2)
2. Rate Limiting rule (classical, Tier 1)
3. Custom Python Rules (extension API + shared utilities)
4. Shared utility refactor (`resolve_field` extraction)

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Tone config | Presets + custom freeform | Presets cover 80%, custom handles edge cases |
| Tone field scope | Developer-specified field | Tone analysis targets AI-generated content, not metadata |
| Custom rules API | Rule subclass (Python-only) | Pattern already exists; decorator sugar is YAGNI |
| Rate limit state | In-memory only | Covers single-process case; pluggable backends deferred |
| Rate limit key | Per-key or global | Per-key is primary use case; global is useful fallback |

## 1. Tone/Sentiment Veto Rule

**Tier 2, LLM-based.** Analyzes a specific payload field for unwanted tone.

### Config

```yaml
- type: tone_sentiment
  field: body
  block: [angry, sarcastic, apologetic, threatening]
  custom: ["sounds legally liable", "promises a specific timeline"]
  provider: anthropic
  model: claude-haiku-4-5-20251001
  api_key_env: ANTHROPIC_API_KEY
```

### Parameters

- `field` (required): dot-notation path to the payload field containing AI-generated text
- `block` (optional): list of preset tone categories to block. Available presets: `angry`, `sarcastic`, `apologetic`, `threatening`, `dismissive`
- `custom` (optional): list of freeform tone descriptions for edge cases
- `provider` (default: `"anthropic"`): LLM provider for classification
- `model` (default: `"claude-haiku-4-5-20251001"`): model for classification
- `api_key` / `api_key_env`: API key or env var name (same pattern as prompt injection rule)

At least one of `block` or `custom` must be provided.

### Evaluation Flow

1. Resolve `field` from payload using `resolve_field`
2. If field is missing or not a string → `Verdict.approved()`
3. Build classification prompt listing all blocked tones (presets + custom)
4. Send to LLM: "Does this text match any of these tones? Respond with the matched tone name or NONE"
5. If LLM returns a tone match → `Verdict.blocked(rule="tone_sentiment", reason="Tone detected: sarcastic", details={"tone": "sarcastic", "field": "body"})`
6. If LLM returns NONE → `Verdict.approved()`
7. If LLM errors → `Verdict.error()`

### LLM Provider Integration

Reuses the same `_call_anthropic` / `_call_openai` pattern from `PromptInjectionRule`. The classification prompt differs but the API call structure is identical.

### File

`agentguard/rules/tone_sentiment.py`

## 2. Rate Limiting Rule

**Tier 1, classical.** Tracks action frequency in-memory and blocks when thresholds are exceeded.

### Config

```yaml
- type: rate_limit
  max_actions: 5
  window_seconds: 3600
  key_field: user_id
```

### Parameters

- `max_actions` (required): maximum number of actions allowed within the window
- `window_seconds` (required): time window in seconds
- `key_field` (optional): dot-notation path to a payload field for per-key rate limiting. If omitted, rate limit is global (all actions share one counter).

### Evaluation Flow

1. If `key_field` is specified, resolve it from payload using `resolve_field`. If missing, approve (consistent with financial rule).
2. If no `key_field`, use `"__global__"` as the key.
3. Acquire async lock for thread safety.
4. Prune timestamps older than `window_seconds` from the key's list.
5. If `len(timestamps) >= max_actions` → `Verdict.blocked()`
6. Otherwise, append current timestamp → `Verdict.approved()`

### State Management

- In-memory `dict[str, list[float]]` mapping keys to timestamp lists
- Protected by `asyncio.Lock` for concurrent access safety
- Expired timestamps pruned on every `evaluate()` call
- State resets on process restart (documented as expected behavior)
- No persistence — pluggable backends deferred to Phase 4

### Verdict on Block

```python
Verdict.blocked(
    rule="rate_limit",
    reason="Rate limit exceeded: 5 actions in 3600s for key 'user_42'",
    details={"key": "user_42", "count": 5, "max_actions": 5, "window_seconds": 3600},
)
```

### File

`agentguard/rules/rate_limit.py`

## 3. Custom Python Rules

**No new rule files.** This formalizes and tests the extension pattern.

### Developer Experience

```python
from agentguard import AgentGuard, Verdict
from agentguard.rules.base import Rule, extract_strings, resolve_field

class NoProfanityRule(Rule):
    tier = 1
    rule_name = "no_profanity"

    BLOCKED_WORDS = {"damn", "hell", "crap"}

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

guard = AgentGuard(rules=[
    NoProfanityRule(),
    PiiDetectionRule(block=["ssn"]),
])
```

### What This Delivers

- Public, stable `Rule` base class for subclassing
- `extract_strings(payload)` and `resolve_field(payload, path)` exported as reusable utilities
- Integration tests proving custom rules work correctly in the pipeline:
  - Custom Tier 1 rule alongside built-in rules
  - Custom Tier 2 rule sorted correctly
  - Custom rule errors handled by `on_error`
  - Mixed pipelines (built-in + custom)

### Constraints

- Custom rules are **Python-only** — no YAML `type:` registration for user-defined rules
- `from_config` is optional for custom rules (only needed if you want YAML support, which requires forking config.py)

## 4. Shared Utility Refactor

### Extract `resolve_field` to `rules/base.py`

Move `_resolve_field` from `agentguard/rules/financial.py` to `agentguard/rules/base.py` as the public function `resolve_field`.

- `FinancialLimitRule` imports from `base.py` instead of using a local function
- `ToneSentimentRule` and `RateLimitRule` import from `base.py`
- Custom rules can import it: `from agentguard.rules.base import resolve_field`

### Updated Exports

`agentguard/rules/base.py` exports: `Rule`, `extract_strings`, `resolve_field`

`agentguard/rules/__init__.py` adds: `ToneSentimentRule`, `RateLimitRule`

`agentguard/__init__.py` adds: `ToneSentimentRule`, `RateLimitRule`

## 5. Config Integration

### Registry Additions

```python
_RULE_REGISTRY = {
    "pii_detection": PiiDetectionRule,
    "financial_limit": FinancialLimitRule,
    "prompt_injection": PromptInjectionRule,
    "tone_sentiment": ToneSentimentRule,
    "rate_limit": RateLimitRule,
}
```

### Validation Additions in `_validate_rule_config`

**tone_sentiment:**
- `field` is required
- `block` entries must be from preset list: `angry`, `sarcastic`, `apologetic`, `threatening`, `dismissive`
- At least one of `block` or `custom` must be provided

**rate_limit:**
- `max_actions` is required, must be a positive integer
- `window_seconds` is required, must be a positive number

## 6. New Files

```
agentguard/rules/tone_sentiment.py       # ToneSentimentRule
agentguard/rules/rate_limit.py           # RateLimitRule
tests/test_rules/test_tone_sentiment.py  # tone/sentiment tests
tests/test_rules/test_rate_limit.py      # rate limit tests
tests/test_custom_rules.py              # custom rule integration tests
```

## 7. Testing Strategy

### Tone/Sentiment Rule Tests

- LLM calls mocked (same pattern as prompt injection)
- Test each preset tone detection via mocked LLM
- Test custom tone descriptions via mocked LLM
- Test field resolution: missing field approves, nested field works
- Test LLM error returns error verdict
- Test `from_config` with presets + custom
- Test validation: invalid preset rejected, missing `field` rejected

### Rate Limit Rule Tests

- Blocks after `max_actions` reached
- Allows actions within limit
- Window expiry: actions outside window don't count
- Per-key isolation: user_a's actions don't affect user_b
- Global mode (no `key_field`): all actions share one counter
- Missing `key_field` in payload approves
- Concurrent access via `asyncio.gather`
- `from_config`

### Custom Rules Integration Tests

- Custom Tier 1 rule works alongside built-in rules
- Custom Tier 2 rule sorted correctly
- Custom rule that returns error handled by `on_error`
- Custom rule uses `extract_strings` and `resolve_field`
- Pipeline with mix of built-in + custom rules

### Config Validation Tests

- `tone_sentiment` without `field` raises `AgentGuardConfigError`
- `tone_sentiment` with invalid preset raises error
- `tone_sentiment` with neither `block` nor `custom` raises error
- `rate_limit` without `max_actions` raises error
- `rate_limit` with negative `window_seconds` raises error

## 8. Dependencies

No new dependencies. Tone/sentiment reuses the existing optional `anthropic` and `openai` dependencies from Phase 1.

## Out of Scope

- Pluggable rate limit backends (Redis, SQLite) — deferred to Phase 4
- YAML registration for custom rules
- Tone preset localization for non-English content
- Decorator shorthand for custom rules
