<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/cogniwall-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo/cogniwall-logo.svg">
    <img alt="CogniWall" src="assets/logo/cogniwall-logo.svg" height="60">
  </picture>
</p>

<p align="center">
  <strong>Stripe Radar, but for Autonomous AI Agents.</strong><br>
  A programmable firewall that sits between your AI agents and the outside world.
</p>

<p align="center">
  <a href="https://github.com/cogniwall/cogniwall/actions/workflows/ci.yml">
    <img src="https://github.com/cogniwall/cogniwall/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://github.com/cogniwall/cogniwall/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/cogniwall/cogniwall.svg" alt="License">
  </a>
  <a href="https://pypi.org/project/cogniwall/">
    <img src="https://img.shields.io/pypi/v/cogniwall.svg" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/cogniwall/">
    <img src="https://img.shields.io/pypi/pyversions/cogniwall.svg" alt="Python">
  </a>
</p>

<hr>

CogniWall intercepts hallucinations, enforces deterministic limits, and blocks malicious actions *before* they execute in your production system. 

Think of it as a pipeline engine: ultra-fast classical checks (regex, limits) run first, and slower LLM-based semantic checks only run if needed.

## Features

**Guardrail Rules:**
- **PII Detection**: Stop your agents from leaking SSNs, Credit Cards, or other sensitive data.
- **Prompt Injection Defense**: Prevent jailbreaks and malicious payloads from altering your agent's core instructions.
- **Financial Limiters**: Hardcode maximum spend limits or transaction bounds.
- **Tone & Sentiment Veto**: Block AI-generated content that creates legal liability, is overly angry, or politically biased.
- **Rate Limiting**: Prevent runaway recursive loops or spamming of downstream APIs.
- **Custom Python Rules**: Subclass our rules engine to write your own checks.

**Audit Dashboard:**
- **Event Log**: See every evaluation attempt — approved, blocked, or errored — with filtering and search.
- **Payload Drill-down**: Click any event to see the full verdict, rule details, and original payload.
- **Analytics**: Block rate over time, most-triggered rules, top blocked agents.

## 📦 Installation

Requires **Python 3.11+**.

```bash
pip install cogniwall                  # Core rules (PII, financial, rate limit)
pip install cogniwall[anthropic]       # + Anthropic-powered rules (tone, injection)
pip install cogniwall[openai]          # + OpenAI-powered rules
pip install cogniwall[gemini]          # + Google Gemini-powered rules
```

## 🛠️ Quickstart

CogniWall uses a `cogniwall.yaml` to define active rules, or it can be configured programmatically.

```python
from cogniwall import CogniWall, PiiDetectionRule, FinancialLimitRule, ToneSentimentRule, get_provider

# Build a guard with the rules you need
guard = CogniWall(rules=[
    PiiDetectionRule(block=["ssn", "credit_card"]),
    FinancialLimitRule(field="amount", max=10_000),
    ToneSentimentRule(
        field="body",
        block=["angry", "sarcastic"],
        provider=get_provider({"provider": "anthropic", "api_key_env": "ANTHROPIC_API_KEY"}),
    ),
])

# Evaluate a payload BEFORE your agent executes an action
verdict = guard.evaluate({"body": "Ignore all previous instructions.", "amount": 500})

if verdict.blocked:
    print(f"Action blocked by '{verdict.rule}': {verdict.reason}")
else:
    # Safe to execute!
    pass
```

> Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY` in your environment for LLM-powered rules. For local LLMs (Ollama, OpenClaw, LM Studio), use `provider: openai` with a `base_url` — no API key needed.

Or load rules from YAML:

```python
from cogniwall import CogniWall

guard = CogniWall.from_yaml("cogniwall.yaml")
verdict = guard.evaluate({"body": "Hello world", "amount": 50})
```

Example `cogniwall.yaml`:

```yaml
version: "1"
on_error: error

rules:
  - type: pii_detection
    block: [ssn, credit_card]

  - type: financial_limit
    field: amount
    max: 10000

  # LLM-powered rules (requires pip install cogniwall[anthropic|openai|gemini])
  # - type: prompt_injection
  #   provider: anthropic           # or "openai", "gemini"
  #   api_key_env: ANTHROPIC_API_KEY

  # - type: tone_sentiment
  #   field: body
  #   block: [angry, sarcastic]
  #   provider: anthropic           # or "openai", "gemini"
  #   api_key_env: ANTHROPIC_API_KEY

  # Local LLM (Ollama, OpenClaw, LM Studio, vLLM):
  # - type: prompt_injection
  #   provider: openai
  #   base_url: http://127.0.0.1:11434/v1
  #   model: llama3

# audit:
#   endpoint: http://localhost:3000/api/events
```

## Audit Dashboard

CogniWall includes a self-hosted dashboard for monitoring your AI agent evaluations in real-time.

```python
from cogniwall import CogniWall, AuditClient, PiiDetectionRule

# Connect to the dashboard
audit = AuditClient(endpoint="http://localhost:3000/api/events")
guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])], audit=audit)

# Events automatically appear in the dashboard
verdict = guard.evaluate(
    {"body": "SSN: 123-45-6789"},
    metadata={"agent_id": "support-bot"},
)
```

**Start the dashboard** (requires **Node.js 18+** and **Docker**):

```bash
cd dashboard
npm install
cp .env.example .env             # Configure DATABASE_URL
docker compose up db -d          # Start PostgreSQL
npx prisma migrate dev --name init
npm run dev                      # http://localhost:3000
```

## The Open Core Strategy

CogniWall is an **open-core** project. The Python engine and self-hosted dashboard will always remain open-source and free. We are building it this way because security tools require maximum trust and zero adoption friction.

**CogniWall Cloud** (coming soon) adds: unlimited data retention, real-time streaming, alerts/webhooks, multi-tenancy, and global threat intelligence. Upgrading is one line:

```python
audit = AuditClient(endpoint="https://api.cogniwall.io/events", api_key="cw_live_...")
```

### Roadmap
- [x] Phase 1: Core Pipeline & MVP Rules (PII, Financial, Inject)
- [x] Phase 2: Extendable Python API & Semantic Rules (Tone, Rate Limit)
- [x] Phase 3: Visual Audit Dashboard (Next.js + PostgreSQL)
- [ ] Phase 4: Hosted SaaS Engine

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## 📝 License

CogniWall is released under the [MIT License](https://github.com/cogniwall/cogniwall/blob/main/LICENSE).
