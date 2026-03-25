# AgentGuard Product Roadmap

## Vision

"Stripe Radar, but for Autonomous AI Agents." A programmable firewall that sits between AI agents and the outside world, intercepting hallucinations, enforcing limits, and blocking malicious actions before they execute.

## Phase 1: Core Python Library (Current)

**Spec:** `docs/superpowers/specs/2026-03-25-agentguard-core-api-design.md`

- `pip install agentguard` — Python library
- Tiered pipeline engine (fast classical checks, then LLM-based checks)
- Three MVP guardrail modules:
  - PII detection (SSN, credit card, email, phone, custom terms)
  - Financial limits (field-specific thresholds)
  - Prompt injection detection (regex pre-filter + LLM fallback)
- YAML + Python configuration
- Verdict-based API (approve/block/error)
- Supports Anthropic and OpenAI as LLM providers

## Phase 2: Additional Guardrail Modules

- **Tone/Sentiment Veto** — block AI-generated content that is angry, sarcastic, or creates legal liability (e.g., unconditional apologies). LLM-based, Tier 2.
- **Custom Python Rules** — let developers author their own `Rule` subclasses for domain-specific logic. Plugin interface for the pipeline.
- **Rate Limiting** — track action frequency per agent/user and block when thresholds are exceeded (e.g., "no more than 5 refunds per hour").

## Phase 3: Audit Dashboard

- Web UI showing all evaluation attempts, blocks, and approvals
- Filterable by rule, time range, agent, verdict status
- Block reason drill-down with payload details
- Analytics: block rate over time, most-triggered rules, top blocked agents
- Tech likely: Next.js frontend, SQLite/Postgres for event storage

## Phase 4: Hosted SaaS API

- Wrap the Python library in a hosted API (`api.agentguard.io/evaluate`)
- Tenant isolation, API key management, usage tracking
- Usage-based pricing:
  - Hobbyist: Free up to 10,000 evaluations/month
  - Pro: $99/mo + $0.005/evaluation over 50k
  - Enterprise: $1,500/mo with custom rules, SLA, zero-data-retention
- Zero-data-retention option for compliance-sensitive customers

## Phase 5: Ecosystem Expansion

- **TypeScript/Node SDK** — second language target, covers n8n, Vercel AI SDK ecosystem
- **Framework integrations** — first-class middleware for LangChain, CrewAI, OpenAI Agents SDK
- **Network effects** — shared prompt injection pattern database across customers (opt-in). When an attack is detected for one customer, it's blocked for all.

---

## Design Decisions Archive

Alternatives discussed during brainstorming and why they were deferred:

| Decision | Options Considered | Chosen | Why |
|----------|-------------------|--------|-----|
| Deployment | A) Hosted SaaS, B) Self-hosted library, C) Library-first then hosted | C | Faster to ship, no infra cost upfront, library becomes the hosted API core |
| Language | A) Python, B) TypeScript, C) Both | A (Python first) | Bulk of agentic AI ecosystem is Python today |
| Evaluator | A) LLM-as-judge only, B) Classical rule engine only, C) Hybrid | C | Classical for deterministic checks (fast, free), LLM only for semantic analysis (flexible) |
| Pipeline | A) Sequential pipeline, B) Parallel fan-out, C) Tiered pipeline | C | Short-circuits cheap checks before expensive LLM calls; parallel within tiers |
| Config | A) Python-only, B) YAML-only, C) Both | C | YAML for simplicity/onboarding, Python for power users |
| Verdict model | A) Return verdict object, B) Raise exceptions, C) Callback/hook system | A | Least surprising, non-invasive, works with any agent framework |

## Go-To-Market Ideas (from idea doc)

- **"Hack The Agent" honeypot** — viral demo where users try to trick a banking AI, AgentGuard blocks attacks in real-time
- **Developer tutorials** — SEO content like "How to secure your LangChain agent against Prompt Injection"
- **Launch on Hacker News / ProductHunt** — frame as "Cloudflare for LLM Agents"
