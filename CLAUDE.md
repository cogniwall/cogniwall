# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install Python lib in dev mode (creates .venv)
pip install -e ".[dev]"

# Run all Python tests
.venv/bin/pytest -v

# Run a single test file
.venv/bin/pytest tests/test_rules/test_pii.py -v

# Run a single test
.venv/bin/pytest tests/test_rules/test_pii.py::TestPiiDetectionRule::test_blocks_ssn -v

# Run tests excluding live LLM tests (default behavior)
.venv/bin/pytest -m "not live_llm"

# Dashboard (Next.js) commands
cd dashboard && npm install
cd dashboard && npm run dev        # Start dev server on :3000
cd dashboard && npm run build      # Production build
cd dashboard && npx prisma generate  # Regenerate Prisma client
cd dashboard && npx prisma migrate dev --name <name>  # Run migrations
cd dashboard && docker compose up db -d  # Start PostgreSQL
```

## Architecture

CogniWall is a Python library that evaluates arbitrary payloads against configurable rules, returning structured verdicts (approve/block/error).

**Evaluation flow:** `CogniWall.evaluate(payload)` → `Pipeline.run(payload)` → rules sorted into tiers → each tier runs in parallel via `asyncio.gather` → first block/error short-circuits.

**Tiered pipeline:** Tier 1 rules (classical: PII, financial limits, rate limiting) run first in parallel. If all approve, Tier 2 rules (LLM-based: prompt injection, tone/sentiment) run in parallel. This avoids wasting LLM calls when a cheap check would block.

**Rule contract:** Every rule extends `Rule` ABC from `rules/base.py` with `tier: int`, `rule_name: str`, `async evaluate(payload) -> Verdict`, and `@classmethod from_config(config) -> Rule`. All rules are async even if classical (for pipeline uniformity).

**Config system:** `config.py` has a `_RULE_REGISTRY` dict mapping YAML type strings to Rule classes. New rules must be added here, plus exported from `rules/__init__.py` and `cogniwall/__init__.py`.

**Shared utilities in `rules/base.py`:** `extract_strings(obj, include_keys=False)` iteratively collects all strings from nested dicts/lists (with circular reference detection). `resolve_field(payload, "dot.path")` navigates nested dicts. Both are public API for custom rules.

**Audit system:** `AuditClient` in `audit.py` captures evaluation events and sends them to a dashboard. Configured via `audit=` param on `CogniWall` or `audit:` section in YAML. Fire-and-forget by default (async queue + background flush loop), with sync opt-in. Uses stdlib `urllib.request` only — no external dependencies. The audit path is non-blocking: failures are logged and never affect the verdict.

**Dashboard:** Self-hosted Next.js app in `dashboard/` directory. PostgreSQL via Prisma ORM. Three API routes (`POST /api/events`, `GET /api/events`, `GET /api/analytics`) and three pages (event log, drill-down, analytics). Tailwind CSS + shadcn/ui + Recharts.

## Key Patterns

**Python 3.14 Verdict compat:** `Verdict` factory classmethods (`approved`, `blocked`, `error`) are defined outside the class body and attached after, to avoid a Python 3.14 behavior change where classmethods shadow dataclass fields. Do not move these methods back into the class.

**LLM provider pattern:** `PromptInjectionRule` and `ToneSentimentRule` both use `_call_llm` → `_call_anthropic` / `_call_openai` with lazy imports. Tests mock at the `_call_llm` level.

**Rate limit state:** `RateLimitRule` uses in-memory `dict[str, list[float]]` with `asyncio.Lock`. State resets on process restart (by design).

**Adding a new rule:** Create `rules/<name>.py` with a `Rule` subclass → add to `_RULE_REGISTRY` in `config.py` → add validation in `_validate_rule_config` → export from `rules/__init__.py` and `cogniwall/__init__.py` → add tests in `tests/test_rules/`.

**Pipeline safety:** `Pipeline.run()` uses `_safe_copy(payload)` (not `copy.deepcopy`) to isolate each rule's view of the payload. `_safe_copy` only handles JSON-serializable types to prevent RCE via `__reduce__`. `asyncio.gather` uses `return_exceptions=True` and converts exceptions to `Verdict.error()`.

**extract_strings safety:** Uses iterative stack-based traversal with `id()`-based visited set for circular reference detection and max depth of 2000. PII rule passes `include_keys=True` to also scan dict keys.
