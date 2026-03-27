# CogniWall Product Roadmap

## Vision

**"Stripe Radar, but for Autonomous AI Agents."** A programmable firewall that sits between AI agents and the outside world, intercepting hallucinations, enforcing limits, and blocking malicious actions before they execute.

**Core Strategy: The Open-Core Model**
The rule-engine pipeline is given away as an open-source Python library to developers to build trust and eliminate adoption friction. Monetization occurs when companies deploy to production and hit the scale that requires the Hosted SaaS infrastructure: the visual Audit Dashboard, centralized API key management, rate-limiting, and global threat intelligence.

## Phase 1: Core Python Library (Open Source Engine - Complete)

**Spec:** `docs/superpowers/specs/2026-03-25-cogniwall-core-api-design.md`

- `pip install cogniwall` — Open-source Python library
- Tiered pipeline engine (fast classical checks, then LLM-based semantic checks)
- Three MVP guardrail modules: PII detection, Financial limits, Prompt injection detection
- YAML + Python configuration
- Verdict-based API (approve/block/error)
- Supports Anthropic and OpenAI as local LLM evaluator providers (Free for developers testing locally)

## Phase 2: Additional Guardrail Modules (Open Source Engine - Complete)

**Spec:** `docs/superpowers/specs/2026-03-25-cogniwall-phase2-design.md`

- **Tone/Sentiment Veto** — block AI-generated content that is angry, sarcastic, or creates legal liability.
- **Custom Python Rules** — public extension API (`Rule` ABC + `extract_strings` / `resolve_field` utilities).
- **Rate Limiting** — in-memory action frequency tracking with per-key isolation.
- **Security hardening** — two rounds of adversarial testing uncovered and fixed: NaN/Inf financial bypasses, regex evasion via unicode/mixed separators, pipeline crash on rule exceptions, payload mutation between concurrent rules, and recursion bombs in payload traversal.

## Phase 3: Audit Dashboard (The "Visual Hook" - Complete)

**Spec:** `docs/superpowers/specs/2026-03-26-phase3-audit-dashboard-design.md`

The transition from a library to a visual product. Two deliverables: a thin `AuditClient` in the Python SDK and a self-hosted Next.js dashboard.

**Python SDK — AuditClient:**
- Non-blocking, fire-and-forget event capture (sync opt-in for compliance)
- Configurable via YAML or Python — follows existing config pattern
- No new dependencies (stdlib `urllib.request`)
- Phase 4 upgrade = change one endpoint URL

**Dashboard Service — Next.js + PostgreSQL:**
- Event log with filtering (status, rule, time range, search)
- Payload drill-down with collapsible JSON viewer
- Analytics: block rate over time, top triggered rules, top blocked agents
- Single deployable (Next.js API routes + Prisma ORM)
- Docker Compose for one-command self-hosting

**Free vs. Premium split:**
- Free (self-host): full event log, drill-down, basic analytics (24h), 7-day retention
- Premium (Cloud): unlimited retention, export, real-time streaming, alerts, multi-tenancy

## Phase 4: CogniWall Cloud (Hosted SaaS API & Monetization)

The monetization engine. Phase 3's `AuditClient(endpoint=...)` pattern means the upgrade path is seamless — developers just point at `api.cogniwall.io` instead of `localhost`.

- Hosted API (`api.cogniwall.io/evaluate`) powered by ultra-fast managed models (e.g., Groq / Mistral-Small) so developers don't have to manage or pay for evaluation models themselves.
- Tenant isolation, API key management (`X-CogniWall-Key` header — plumbing built in Phase 3), and global rate limiting across servers.
- Real-time WebSocket streaming for live dashboard updates.
- Alerts / webhooks on block spikes (Slack, email).
- Payload auto-redaction (automatically mask PII-triggering fields before storage).
- Configurable data retention (30d/90d/unlimited).
- **Usage-based pricing:**
  - **Hobbyist:** Free up to 10,000 evaluations/month
  - **Pro:** $99/mo + $0.005/evaluation over 50k
  - **Enterprise:** $1,500/mo Custom rules, SLA, strict zero-data-retention options.

## Phase 5: Ecosystem Expansion

- **TypeScript/Node SDK** — wrap the REST API for the JS ecosystem.
- **Framework integrations** — drop-in middleware for LangChain (Python & JS), CrewAI, Vercel AI SDK, and n8n.
- **Global Threat Intelligence** — shared prompt injection pattern database across CogniWall Cloud customers (opt-in).

## Future Ideas (Backlog)

- **Pluggable rate limit backends** — Redis/SQLite storage for rate limiting across processes.
- **Rate limit decorator shorthand** — `@cogniwall.rule` syntax.
- **Composite/chained rules** — rules that depend on other rules' verdicts (AND/OR logic).
- **Verdict callbacks/webhooks** — real-time alerting on blocked actions.
- **Cost tracking per evaluation** — track estimated token cost.
- **Payload redaction** — sanitize PII and pass the modified payload rather than just blocking.
- **Base64/encoding-aware PII scanning** — detect PII hidden in base64, URL-encoding, or other encodings (identified in adversarial testing).
- **Per-rule timing breakdown** — currently only whole-pipeline `elapsed_ms` is tracked; per-rule metrics would enable performance profiling in the dashboard.
- **Event retry / dead letter queue** — AuditClient currently drops events on failure; retry with backoff + local buffer for reliability.
- **Table partitioning** — partition `audit_events` by month when data volume exceeds ~10M rows.

---

## Design Decisions Archive

| Decision | Chosen | Why |
|----------|--------|-----|
| Strategy | **Open-Core** | Security tools require trust. The OSS engine acts as top-of-funnel marketing; monetize the hosted infrastructure (SaaS). |
| Evaluator | **Hybrid** | Classical rules for deterministic checks (fast, free), LLM for semantic analysis (flexible). |
| Pipeline | **Tiered** | Short-circuits cheap regex checks before triggering expensive LLM calls. |
| Config | **YAML + Python** | YAML for fast onboarding, Python subclassing for power users. |
| Verdict model | **Return Object** | Least surprising, non-invasive compared to throwing exceptions. |
| Audit delivery | **Fire-and-forget (async default)** | Zero latency overhead on evaluate(); sync opt-in for compliance. |
| Audit auth | **Optional API key** | Zero friction for local dev; plumbing ready for Cloud multi-tenancy. |
| Payload storage | **Opt-in** | Safe default avoids storing sensitive data; developers enable when needed. |
| Dashboard stack | **Next.js monolith** | Single deployable; API routes + SSR in one process; minimal ops for self-hosters. |
| Pipeline safety | **deepcopy + return_exceptions** | Adversarial testing proved rules can mutate shared payloads and crash pipelines. |

---

## Phased Launch Strategy

Because engineering velocity is extremely high (using AI agents), a **Staggered Launch Strategy** is highly recommended to maximize marketing leverage and validate features before scaling:

1. **Launch 1: Open Source Library (Phases 1 & 2)** — Launch immediately on Hacker News, r/LangChain, and Twitter. Focus: Gather organic stars and discover what custom rules developers desperately need while building trust.
2. **Launch 2: The Visual Demo (Phase 3)** — Launch the interactive dashboard. Focus: Viral marketing (Honeypot) and proving value to non-technical decision-makers.
3. **Launch 3: Hosted SaaS (Phase 4)** — Massive launch on Product Hunt ("Cloudflare for AI Agents"). Focus: Conversion to Pro/Enterprise tiers.
4. **Launch 4+: Ecosystem Drops (Phase 5)** — Continuous, targeted mini-launches for specific communities (e.g., n8n forums, Vercel developers).

## Security Posture

Two rounds of adversarial testing (200+ test cases) have hardened the engine:

**Fixed:** NaN/Inf financial bypasses, unicode/mixed-separator regex evasion, pipeline crash on rule exceptions, payload mutation between concurrent rules, deep recursion/circular reference bombs, extract_strings ignoring tuples/sets/bytes, case-sensitive tone matching, config accepting invalid params.

**Known remaining (LOW/design-level):** base64-encoded PII evasion, prompt injection obfuscation (leetspeak, homoglyphs), financial rule type coercion (Decimal, string numerics), split-across-fields attacks. These are tracked in `tests/test_adversarial.py` and `tests/test_adversarial_r2.py`.

## AI-Driven Marketing Playbook

Leveraging your team of agents, you can scale outbound marketing as fast as you write code:

- **AI Outbound Sales (GitHub Scraping):** Deploy an agent to scan GitHub for new projects using raw OpenAI/Anthropic SDKs or LangChain. The agent automatically runs static analysis to find prompt injection vulnerabilities, and emails the maintainers (or opens a PR!) showing how CogniWall fixes their exact vulnerability in 3 lines of code.
- **AI-Automated Content Engine:** Use an agent to monitor Reddit/StackOverflow for questions about LLM safety or hallucinations. Automatically generate completely accurate, long-form, SEO-optimized technical tutorials on your blog bridging their exact issue to an CogniWall solution.
- **Hyper-Personalized Demo Generation:** For B2B outreach, create an agent pipeline that visits a prospect's website, automatically hallucinates a scenario where their tool breaks, and generates a Loom-style synthetic video showing how CogniWall protects them.
- **The "Hack The Agent" Honeypot:** Launch a standalone, viral web app natively defended by CogniWall. Challenge the dev community: "Trick this AI into releasing the CEO's secret, win $1,000." Show a live public dashboard of CogniWall blocking thousands of real-time attacks.
