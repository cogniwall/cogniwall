# AgentGuard Product Roadmap

## Vision

"Stripe Radar, but for Autonomous AI Agents." A programmable firewall that sits between AI agents and the outside world, intercepting hallucinations, enforcing limits, and blocking malicious actions before they execute.

## Phase 1: Core Python Library (Complete)

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

## Phase 2: Additional Guardrail Modules (Current)

**Spec:** `docs/superpowers/specs/2026-03-25-agentguard-phase2-design.md`

- **Tone/Sentiment Veto** — block AI-generated content that is angry, sarcastic, or creates legal liability. LLM-based, Tier 2. Preset tones (angry, sarcastic, apologetic, threatening, dismissive) + custom freeform descriptions. Scans a developer-specified field, not full payload.
- **Custom Python Rules** — public extension API: developers subclass `Rule` and pass instances directly. Shared utilities (`extract_strings`, `resolve_field`) exported for reuse. No YAML registration for custom rules.
- **Rate Limiting** — in-memory action frequency tracking. Configurable per-key (e.g., per user_id) or global. Blocks when threshold exceeded within time window. State resets on process restart.

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

## Future Ideas (Backlog)

Ideas surfaced during design that don't fit current phases but are worth tracking:

- **Pluggable rate limit backends** — Redis/SQLite storage for rate limiting across processes and restarts. Natural addition when hosted API (Phase 4) needs shared state.
- **Rate limit decorator shorthand** — `@agentguard.rule(tier=1, name="my_rule")` decorator for simple custom rules. Deferred in favor of subclass approach (YAGNI), but could reduce boilerplate for trivial rules.
- **Composite/chained rules** — rules that depend on other rules' verdicts (e.g., "block if PII detected AND financial amount > $50"). Requires pipeline changes.
- **Verdict callbacks/webhooks** — fire a webhook or callback on block/error for real-time alerting, before the audit dashboard exists.
- **Cost tracking per evaluation** — track estimated LLM token cost for each evaluation. Useful for the hosted API pricing model.
- **Rule dry-run mode** — evaluate rules but return "would have blocked" without actually blocking. Useful for gradual rollout of new rules.
- **Payload redaction** — instead of just blocking, optionally redact PII and pass the cleaned payload through. An alternative to binary approve/block.
- **Multi-language tone presets** — tone/sentiment presets localized for non-English content.

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
| Tone config | A) Blocked tones only, B) Custom definitions, C) Presets + custom | C | Presets cover 80%, custom handles edge cases |
| Tone field scope | A) Entire payload, B) Specific field, C) Field with fallback | B | Tone analysis targets AI-generated content, not metadata |
| Custom rules API | A) Rule subclass, B) Decorator, C) Both | A | Subclass pattern already exists and works; decorator is sugar |
| Rate limit state | A) In-memory, B) Pluggable backend, C) Skip for now | A | Covers single-process case; pluggable deferred to Phase 4 |
| Rate limit key | A) Developer-specified field, B) Global only, C) Both | C | Per-key is primary use case; global is useful fallback |

## Go-To-Market Ideas (from idea doc)

- **"Hack The Agent" honeypot** — viral demo where users try to trick a banking AI, AgentGuard blocks attacks in real-time
- **Developer tutorials** — SEO content like "How to secure your LangChain agent against Prompt Injection"
- **Launch on Hacker News / ProductHunt** — frame as "Cloudflare for LLM Agents"
