# CogniWall Phase 3: Audit Dashboard — Design Spec

## Overview

Phase 3 transitions CogniWall from a Python library into a visual product. It adds an `AuditClient` to the Python SDK that sends evaluation events to a self-hosted Next.js dashboard backed by PostgreSQL. The dashboard provides an event log, payload drill-down, and analytics charts.

This spec covers:
1. AuditClient (Python SDK addition)
2. Dashboard API (Next.js API routes)
3. Database schema (PostgreSQL via Prisma)
4. Dashboard UI (three pages)
5. Free vs. premium feature split
6. Deployment and developer experience

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Architecture | SDK + separate service | Clean separation; endpoint swap enables Phase 4 Cloud upgrade |
| AuditClient activation | YAML + programmatic | Follows existing config pattern |
| Event delivery | Fire-and-forget default, sync opt-in | Zero overhead for most users; sync for compliance |
| Auth | Optional API key | Zero friction locally; plumbing ready for Cloud |
| Payload storage | Opt-in (off by default) | Safe default; avoids storing sensitive data |
| Dashboard stack | Next.js API routes (single deployable) | Minimal ops; one process to run |
| Repo structure | Monorepo (`dashboard/` directory) | Discoverable; avoids cross-repo coordination |
| Database | PostgreSQL via Prisma | Battle-tested, JSONB support, Prisma for type-safe queries |
| Styling | Tailwind CSS + shadcn/ui | Fast to build, professional look, dark theme |
| Charts | Recharts | Lightweight, React-native, sufficient for MVP |

## 1. System Overview & Data Flow

### Components

```
Python App                    Dashboard Service              Browser
+-----------------+          +----------------------+       +----------+
| CogniWall       |  HTTP    | Next.js App           |       | Dashboard|
|  +- AuditClient |--------> |  POST /api/events     |       |   UI     |
|     (queue +    |          |  GET  /api/events     |<----->|          |
|      flush)     |          |  GET  /api/analytics  |       |          |
+-----------------+          |  PostgreSQL (Prisma)  |       +----------+
                             +----------------------+
```

### Event Lifecycle

1. `CogniWall.evaluate(payload)` runs as normal, returns `Verdict`
2. If `AuditClient` is configured, it captures an `AuditEvent` (verdict + metadata + optional payload) and enqueues it
3. Background flush loop batches events and POSTs to `POST /api/events`
4. Dashboard API validates, stores in PostgreSQL
5. Dashboard UI queries events and analytics via `GET` endpoints

### Key Principle

The audit path is **non-blocking and non-breaking**. If the dashboard is down or the AuditClient fails, `evaluate()` still returns the correct verdict. Audit failures are logged via `logging.getLogger("cogniwall.audit")` and silently discarded.

## 2. AuditClient (Python SDK)

### Location

`cogniwall/audit.py` — new file in the existing library.

### Public API

```python
from cogniwall import CogniWall, AuditClient

audit = AuditClient(
    endpoint="http://localhost:3000/api/events",
    api_key=None,                # optional
    include_payload=False,       # opt-in
    flush_mode="async",          # or "sync"
    flush_interval=5.0,          # seconds between flushes
    batch_size=50,               # max events per POST
)
guard = CogniWall(rules=[...], audit=audit)
```

### YAML Configuration

```yaml
audit:
  endpoint: http://localhost:3000/api/events
  # api_key_env: COGNIWALL_AUDIT_KEY
  # include_payload: false
  # flush_mode: async
```

### Internals

- **Event capture:** After `Pipeline.run()` returns a verdict, `CogniWall` builds an `AuditEvent` dict and passes it to `AuditClient.record(event)`
- **Queue:** In-memory `collections.deque` with a configurable max size (default 10,000). Oldest events dropped if queue fills up.
- **Flush loop:** `asyncio.Task` that wakes every `flush_interval` seconds, drains up to `batch_size` events, and POSTs them as a JSON array
- **Sync mode:** When `flush_mode="sync"`, `record()` POSTs immediately instead of queueing
- **HTTP client:** `urllib.request` (stdlib) to avoid adding dependencies
- **Failure handling:** Failed POSTs are logged via `logging.getLogger("cogniwall.audit")` and silently discarded. No retries in MVP.

### AuditEvent Schema

```json
{
  "event_id": "uuid-v4",
  "timestamp": "2026-03-26T12:00:00Z",
  "status": "blocked",
  "rule": "pii_detection",
  "reason": "PII detected: ssn",
  "details": {"matched": ["***"], "type": "ssn"},
  "elapsed_ms": 12.3,
  "payload": null,
  "metadata": {"agent_id": "support-bot-1"}
}
```

- `payload` is `null` unless `include_payload=True`
- `metadata` is an optional dict passed into `evaluate()` for contextual info (agent ID, session ID, etc.)

### Change to evaluate() Signature

```python
# Current
guard.evaluate(payload: dict) -> Verdict

# New — metadata is optional, backward-compatible
guard.evaluate(payload: dict, metadata: dict | None = None) -> Verdict
guard.evaluate_async(payload: dict, metadata: dict | None = None) -> Verdict
```

### Changes to Existing Files

- **`cogniwall/guard.py`:** Accept optional `audit: AuditClient | None = None` in constructor. After `Pipeline.run()` returns a verdict, call `audit.record(event)` if audit is configured. Pass `metadata` through `evaluate()` / `evaluate_async()`.
- **`cogniwall/config.py`:** Parse optional `audit:` section from YAML config. Construct `AuditClient` from config dict. `load_config()` returns audit client alongside rules.
- **`cogniwall/__init__.py`:** Export `AuditClient` in `__all__`.
- **`from_yaml` behavior:** If the YAML file contains an `audit:` section, `CogniWall.from_yaml()` automatically creates and attaches the `AuditClient`. An external `audit=` kwarg can also be passed to `from_yaml()` to override the YAML config.

## 3. Dashboard API (Next.js API Routes)

### `POST /api/events` — Event Ingestion

- Accepts a JSON array of `AuditEvent` objects (batch insert)
- Validates schema, rejects malformed events
- If API key is configured on the server, validates `X-CogniWall-Key` header
- Inserts into PostgreSQL via Prisma
- Returns `{ "accepted": 47, "rejected": 3, "errors": [...] }`

### `GET /api/events` — Event List & Drill-down

Query params for filtering:
- `?status=blocked` — filter by verdict status (approved/blocked/error)
- `?rule=pii_detection` — filter by rule name
- `?from=2026-03-25T00:00:00Z&to=2026-03-26T00:00:00Z` — time range
- `?search=ssn` — full-text search across reason/details
- `?page=1&limit=50` — pagination
- `?event_id=uuid` — single event drill-down (returns full payload if stored)

Returns:
```json
{
  "events": [...],
  "total": 1234,
  "page": 1,
  "pages": 25
}
```

### `GET /api/analytics` — Aggregated Metrics

Query params:
- `?from=...&to=...` — time range (default: last 24h)
- `?interval=hour` — bucket size (hour/day/week)

Returns:
```json
{
  "summary": {
    "total": 5000,
    "approved": 4200,
    "blocked": 750,
    "errors": 50,
    "block_rate": 0.15
  },
  "over_time": [
    {"bucket": "2026-03-26T10:00:00Z", "approved": 120, "blocked": 30, "errors": 2}
  ],
  "top_rules": [
    {"rule": "pii_detection", "count": 400},
    {"rule": "rate_limit", "count": 250}
  ],
  "top_blocked_agents": [
    {"agent_id": "support-bot-1", "blocked_count": 180}
  ]
}
```

Note: `top_blocked_agents` requires `metadata.agent_id` to be present in events. If no events have agent metadata, this array is empty.

## 4. Database Schema

PostgreSQL via Prisma. Single table for MVP.

```sql
CREATE TABLE audit_events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      UUID UNIQUE NOT NULL,       -- client-generated, for dedup
  timestamp     TIMESTAMPTZ NOT NULL,
  status        TEXT NOT NULL,               -- 'approved' | 'blocked' | 'error'
  rule          TEXT,                        -- null if approved
  reason        TEXT,                        -- null if approved
  details       JSONB,                       -- rule-specific data
  elapsed_ms    FLOAT NOT NULL,
  payload       JSONB,                       -- null unless include_payload=true
  metadata      JSONB,                       -- agent_id, session_id, etc.
  created_at    TIMESTAMPTZ DEFAULT NOW()    -- server receipt time
);

CREATE INDEX idx_events_timestamp ON audit_events (timestamp DESC);
CREATE INDEX idx_events_status ON audit_events (status);
CREATE INDEX idx_events_rule ON audit_events (rule);
CREATE INDEX idx_events_agent ON audit_events ((metadata->>'agent_id'));
```

### Design Decisions

- **`event_id` for dedup:** If the AuditClient retries a flush (future enhancement), duplicate events are rejected via the unique constraint
- **`details` and `metadata` as JSONB:** Flexible, queryable, no schema migration needed when rules add new detail fields
- **`payload` as JSONB:** Only populated when opted in. Stored as-is from the evaluation call
- **No partitioning for MVP:** Table partitioning by month can be added later when data volume warrants it
- **Free tier retention (7 days):** Enforced by a daily cron job: `DELETE FROM audit_events WHERE timestamp < NOW() - INTERVAL '7 days'`. Premium retention is just a longer interval.

## 5. Dashboard UI

### Page 1: Event Log (`/`)

Main page of the dashboard.

- **Filter bar** at top: status dropdown, rule dropdown, date range picker, search box
- **Data table** with columns: timestamp, status (color-coded badge), rule, reason, agent (from metadata), latency
- **Pagination** at bottom
- Click any row to navigate to drill-down

### Page 2: Event Drill-down (`/events/[id]`)

Detail view for a single event.

- **Breadcrumb:** Events > Event {id}
- **Summary card:** Status badge, event ID, timestamp, rule, latency, agent
- **Block reason section:** Reason text + formatted details key-value pairs
- **Payload viewer** (collapsible JSON tree): Shown only if payload was stored. Otherwise displays: "Payload not captured. Enable `include_payload` to store payloads."
- **Metadata section:** Formatted key-value pairs from metadata dict

### Page 3: Analytics (`/analytics`)

Charts and metrics overview.

- **Summary cards** (row of 4): total evaluations, block rate %, blocked count, error count
- **Evaluations over time:** Area chart with stacked approved/blocked/error, configurable interval
- **Top triggered rules:** Horizontal bar chart
- **Top blocked agents:** Horizontal bar chart
- Date range selector applies to all charts

### Tech Choices

- **Styling:** Tailwind CSS + shadcn/ui (tables, badges, cards, dropdowns)
- **Charts:** Recharts
- **Data fetching:** Next.js Server Components
- **No auth UI for MVP:** API key is set via environment variable on the server

### Stitch Mockups

Visual mockups are available in Stitch project `6241566588061597087` (CogniWall Audit Dashboard).

## 6. Free vs. Premium Feature Split

| Feature | Free (self-host) | Premium (Cloud) |
|---------|-----------------|-----------------|
| Event log + filtering | Full | Full |
| Payload drill-down | Full | Full |
| Analytics (block rate, top rules) | Basic (last 24h) | Unlimited retention + export |
| Multi-tenancy / API keys | — | Per-team dashboards |
| Real-time streaming | — | WebSocket live feed |
| Global threat intelligence | — | Cross-customer pattern sharing |
| Data retention | 7 days | Configurable (30d/90d/unlimited) |
| Alerts / webhooks | — | Slack/email on block spikes |

The free tier is compelling enough to get developers hooked (full event log + drill-down). Analytics depth, retention, team features, and alerting drive upgrades to Cloud.

## 7. Deployment & Developer Experience

### Self-hosted Quick Start

```bash
# 1. Start the dashboard
git clone https://github.com/cogniwall/cogniwall
cd cogniwall/dashboard
cp .env.example .env   # Set DATABASE_URL
npm install
npx prisma migrate dev
npm run dev             # -> http://localhost:3000
```

```python
# 2. Connect your Python app
from cogniwall import CogniWall, AuditClient

audit = AuditClient(endpoint="http://localhost:3000/api/events")
guard = CogniWall.from_yaml("cogniwall.yaml", audit=audit)

verdict = guard.evaluate({"body": "Process refund for SSN 123-45-6789"})
# -> Event automatically appears in dashboard
```

### Docker Alternative

```bash
docker compose up   # Starts PostgreSQL + Next.js dashboard
```

### Phase 4 Upgrade Path

```python
# Self-hosted -> Cloud: just change the endpoint
audit = AuditClient(
    endpoint="https://api.cogniwall.io/events",
    api_key="cw_live_abc123",
)
```

## 8. New Files

### Python Library (new + modified files)

```
cogniwall/audit.py              # AuditClient (new)
cogniwall/guard.py              # Accept audit param, call record after evaluate (modify)
cogniwall/config.py             # Parse audit: YAML section (modify)
cogniwall/__init__.py           # Export AuditClient (modify)
tests/test_audit.py             # AuditClient unit tests (new)
tests/test_guard.py             # Update for audit integration (modify)
tests/test_config.py            # Update for audit config parsing (modify)
```

### Dashboard (new `dashboard/` directory)

```
dashboard/
  package.json
  next.config.js
  .env.example
  docker-compose.yml
  prisma/
    schema.prisma               # Database schema
  src/
    app/
      layout.tsx                # Root layout with sidebar
      page.tsx                  # Event log (main page)
      events/[id]/page.tsx      # Event drill-down
      analytics/page.tsx        # Analytics charts
      api/
        events/route.ts         # POST (ingest) + GET (list/filter)
        analytics/route.ts      # GET (aggregated metrics)
    components/
      sidebar.tsx               # Navigation sidebar
      event-table.tsx           # Event log table
      event-filters.tsx         # Filter bar
      event-detail.tsx          # Drill-down view
      payload-viewer.tsx        # Collapsible JSON tree
      analytics-cards.tsx       # Summary metric cards
      charts/
        evaluations-chart.tsx   # Area chart over time
        top-rules-chart.tsx     # Horizontal bar chart
        top-agents-chart.tsx    # Horizontal bar chart
    lib/
      prisma.ts                 # Prisma client singleton
      queries.ts                # Database query helpers
      validation.ts             # Event schema validation
```

## 9. Testing Strategy

### AuditClient Tests

- Event capture after evaluate() returns verdict
- Queue overflow behavior (oldest events dropped)
- Async flush loop batching
- Sync mode immediate POST
- Failed POST silently logged (not raised)
- Metadata passthrough
- include_payload opt-in behavior
- Backward compatibility (no audit = no change)

### Dashboard API Tests

- `POST /api/events` with valid batch
- `POST /api/events` with malformed events (partial reject)
- `POST /api/events` with API key validation
- `GET /api/events` with each filter combination
- `GET /api/events` single event drill-down
- `GET /api/analytics` with time range and interval
- Dedup via event_id unique constraint

### Integration Tests

- End-to-end: Python evaluate() -> AuditClient -> Dashboard API -> PostgreSQL -> Dashboard UI query
- Dashboard down: evaluate() still returns correct verdict, events silently dropped

## 10. Dependencies

### Python Library

No new required dependencies. `urllib.request` (stdlib) is used for HTTP.

### Dashboard

- `next` (React framework)
- `@prisma/client` + `prisma` (database ORM)
- `tailwindcss` (styling)
- `shadcn/ui` components
- `recharts` (charts)

## Out of Scope

- Real-time WebSocket streaming (premium, Phase 4)
- Multi-tenancy / team dashboards (Phase 4)
- Alerts / webhooks on block spikes (premium, Phase 4)
- Payload auto-redaction (premium feature, deferred)
- Event retry / dead letter queue (future AuditClient enhancement)
- Table partitioning (add when data volume warrants it)
- Authentication UI (API key is env var for MVP)
