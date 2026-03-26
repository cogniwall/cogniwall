# CogniWall Core API & Guardrail Modules — Design Spec

## Overview

CogniWall is a Python library (`pip install cogniwall`) that acts as a programmable firewall for autonomous AI agents. It intercepts payloads before they reach external APIs and evaluates them against developer-configured rules to detect PII leaks, financial limit violations, and prompt injection attacks.

This spec covers the first sub-project: the core evaluation API and three MVP guardrail modules. The audit dashboard and user management are separate follow-up sub-projects.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Deployment model | Library-first, hosted API later | Faster to ship, no infra cost, library becomes the API core |
| Language | Python | Where most LLM agent frameworks live |
| Evaluator backend | Hybrid (classical + LLM) | Classical for deterministic checks, LLM only for semantic analysis |
| MVP guardrails | PII, Financial Limits, Prompt Injection | Highest-severity failure modes for production agents |
| Configuration | YAML + Python | YAML for standard rules, Python for custom logic |
| Verdict model | Return verdict object | Least surprising, non-invasive, framework-agnostic |
| Execution model | Tiered pipeline | Short-circuits cheap checks before expensive LLM calls |

## 1. Library API Surface

### Initialization

```python
from cogniwall import CogniWall

# From YAML config
guard = CogniWall.from_yaml("cogniwall.yaml")

# From Python
guard = CogniWall(
    rules=[
        PiiDetectionRule(block=["ssn", "credit_card", "email"]),
        FinancialLimitRule(max_amount=100, field="amount"),
        PromptInjectionRule(),
    ]
)
```

### Evaluation

```python
verdict = guard.evaluate(payload={
    "to": "user@example.com",
    "subject": "Your refund",
    "body": "Your SSN 123-45-6789 has been verified. Refund of $5000 issued.",
})

if verdict.blocked:
    print(verdict.reason)    # "PII detected: SSN"
    print(verdict.rule)      # "pii_detection"
    print(verdict.details)   # {"matched": ["123-45-6789"], "type": "ssn"}
else:
    send_email(payload)
```

### Async Support

```python
verdict = await guard.evaluate_async(payload={...})
```

### Verdict Dataclass

```python
@dataclass
class Verdict:
    status: Literal["approved", "blocked", "error"]
    blocked: bool           # True if status == "blocked"
    rule: str | None        # which rule triggered the block
    reason: str | None      # human-readable reason
    details: dict | None    # rule-specific metadata
    error: Exception | None # populated when status == "error"
    elapsed_ms: float       # total evaluation time
```

- `evaluate()` is sync by default, `evaluate_async()` for async contexts.
- The payload is an arbitrary `dict`. CogniWall inspects the values, not the structure.
- YAML and Python config are interchangeable — YAML deserializes into the same rule objects.

## 2. Tiered Pipeline Engine

### Architecture

Two tiers of guardrail execution:

- **Tier 1 (Fast/Classical):** PII detection, financial limits. Sub-millisecond. Run in parallel via `asyncio.gather`.
- **Tier 2 (LLM-based):** Prompt injection detection. 50-200ms. Run in parallel within the tier.

### Flow

```
payload
  → Tier 1: [PII Guard, Financial Guard] (parallel)
  → if any blocked → return Verdict(blocked)
  → Tier 2: [Prompt Injection Guard] (parallel)
  → if any blocked → return Verdict(blocked)
  → return Verdict(approved)
```

### Engine Interface

```python
class Pipeline:
    tiers: list[list[Rule]]

    async def run(self, payload: dict) -> Verdict:
        for tier in self.tiers:
            verdicts = await asyncio.gather(
                *[rule.evaluate(payload) for rule in tier]
            )
            blocked = [v for v in verdicts if v.blocked]
            if blocked:
                return blocked[0]
        return Verdict(status="approved", ...)
```

### Rule Base Class

```python
class Rule(ABC):
    @abstractmethod
    async def evaluate(self, payload: dict) -> Verdict:
        ...

    @classmethod
    @abstractmethod
    def from_config(cls, config: dict) -> "Rule":
        """Construct from YAML/dict config."""
        ...
```

- All rules implement the same async interface. Classical rules return immediately.
- Tier assignment is determined by rule type — classical rules register as Tier 1, LLM rules as Tier 2. The pipeline auto-sorts.
- Within a tier, if multiple rules block, the first by list order is returned.

## 3. Guardrail Modules

### 3.1 PII Detection (Tier 1, Classical)

Regex patterns + optional Microsoft Presidio for NER-based detection.

**Capabilities:**
- Built-in patterns: SSN, credit card (Luhn-validated), email, phone number
- Custom terms: developer-provided blocklist strings (e.g., "Project Titan")
- Recursive payload scanning: walks nested dicts/lists, scans all string values

**Config:**
```yaml
- type: pii_detection
  block: [ssn, credit_card, email]
  custom_terms: ["Project Titan", "internal-api-key"]
  use_presidio: false
```

### 3.2 Financial Limits (Tier 1, Classical)

Scans payload for numeric values exceeding a threshold.

**Capabilities:**
- Field-specific: developer specifies which field(s) to check
- Nested field support: dot-notation paths like `data.refund.amount`
- Comparison operators: `max` (default), `min`, `range`

**Config:**
```yaml
- type: financial_limit
  field: amount
  max: 100
```

### 3.3 Prompt Injection Detection (Tier 2, LLM-based)

Classifies whether user input contains prompt injection attempts.

**Capabilities:**
- Regex pre-filter: catches known patterns ("ignore previous instructions", etc.) — blocks immediately without an LLM call
- LLM fallback: for inputs passing the pre-filter, sends to a fast LLM with a classification prompt
- Configurable provider/model: developer provides their own API key. MVP supports both `anthropic` and `openai` providers.

**Config:**
```yaml
- type: prompt_injection
  provider: anthropic
  model: claude-haiku-4-5-20251001
  api_key_env: ANTHROPIC_API_KEY
```

## 4. YAML Configuration

### Full Config Example

```yaml
version: "1"

on_error: block  # or "approve" or "error" (default)

rules:
  - type: pii_detection
    block: [ssn, credit_card]
    custom_terms: ["Project Titan"]

  - type: financial_limit
    field: amount
    max: 100

  - type: prompt_injection
    provider: anthropic
    model: claude-haiku-4-5-20251001
    api_key_env: ANTHROPIC_API_KEY
```

Rules are validated at load time. Unknown types, missing required fields, or invalid values raise `CogniWallConfigError` with clear messages.

## 5. Package Structure

```
cogniwall/
├── __init__.py          # exports CogniWall, Verdict
├── guard.py             # CogniWall class — from_yaml(), evaluate(), evaluate_async()
├── pipeline.py          # Pipeline engine — tier sorting, parallel execution
├── verdict.py           # Verdict dataclass
├── config.py            # YAML loading, validation, schema
├── rules/
│   ├── __init__.py      # exports all rule classes
│   ├── base.py          # Rule ABC
│   ├── pii.py           # PiiDetectionRule
│   ├── financial.py     # FinancialLimitRule
│   └── prompt_injection.py  # PromptInjectionRule
└── patterns/
    ├── __init__.py
    ├── ssn.py           # SSN regex patterns
    ├── credit_card.py   # CC patterns + Luhn validation
    └── common.py        # email, phone, shared utilities

tests/
├── test_guard.py        # integration tests — full evaluate() flow
├── test_pipeline.py     # pipeline engine unit tests
├── test_rules/
│   ├── test_pii.py
│   ├── test_financial.py
│   └── test_prompt_injection.py
├── test_config.py       # YAML loading/validation tests
└── fixtures/            # sample payloads, configs

pyproject.toml
cogniwall.yaml          # example config
```

## 6. Error Handling

### Configuration Errors (Fail Fast)

Raised at load time as `CogniWallConfigError`:
- Unknown rule type
- Missing required fields
- Invalid values (e.g., negative thresholds)
- YAML syntax errors (wrapped with file context)

### Runtime Errors

Returned as verdicts, not exceptions:
- LLM API failures (timeout, auth, rate limit) → `Verdict(status="error", error=<exception>)`
- Payload is not a dict → `TypeError` immediately
- Empty payload → approved (nothing to scan)
- Non-string/non-numeric values in payload → skipped by scanners

### Error Behavior Configuration

```yaml
on_error: error  # default
```

- `error` (default): return the error verdict, developer handles it
- `block`: treat errors as blocks (fail-closed, safer)
- `approve`: treat errors as approvals (fail-open)

`block` is recommended for production and documented as such.

## 7. Testing Strategy

### Unit Tests

- **PII rules:** each pattern with matches, near-misses, edge cases. Custom terms. Recursive scanning.
- **Financial rules:** threshold comparisons, dot-notation paths, missing fields, non-numeric values.
- **Prompt injection:** regex pre-filter with known attacks and benign inputs. LLM fallback with mocks.
- **Config:** valid YAML loading, each validation error case, unknown rule types.
- **Pipeline:** tier sorting, parallel execution, short-circuiting, error propagation, `on_error` modes.

### Integration Tests

Full `evaluate()` flow: load YAML, evaluate payloads, assert verdicts. Multi-rule triggers, all-pass, error scenarios.

### LLM Tests

Marked with `@pytest.mark.live_llm`, skipped by default. Developers run locally by setting API key env vars.

### Tooling

- `pytest` as test runner
- `pytest-asyncio` for async tests
- `unittest.mock` for mocks — no other test dependencies

## 8. Dependencies

### Required
- `pyyaml` — YAML config parsing

### Optional
- `presidio-analyzer` — enhanced PII/NER detection (opt-in via `use_presidio: true`)
- `anthropic` — for prompt injection detection with Claude models
- `openai` — for prompt injection detection with OpenAI models

### Dev
- `pytest`
- `pytest-asyncio`

## Out of Scope (Future Sub-Projects)

- Audit dashboard (frontend UI)
- User/API key management
- Hosted SaaS API wrapper
- Tone/sentiment veto guardrail
- Custom Python rule authoring (developer-defined Rule subclasses — deferred for MVP; the built-in Python API for configuring rules is in scope)
