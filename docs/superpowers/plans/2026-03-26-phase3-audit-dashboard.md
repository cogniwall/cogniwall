# CogniWall Phase 3: Audit Dashboard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `AuditClient` to the Python SDK and build a self-hosted Next.js dashboard for viewing evaluation events, drill-down details, and analytics.

**Architecture:** Thin AuditClient in Python posts events via HTTP to a Next.js dashboard backed by PostgreSQL (Prisma ORM). The audit path is non-blocking — if the dashboard is down, evaluate() still works. Two independent subsystems: Python SDK (Tasks 1-4) and Dashboard (Tasks 5-11).

**Tech Stack:** Python 3.11+ (stdlib only for AuditClient), Next.js 15, PostgreSQL, Prisma, Tailwind CSS, shadcn/ui, Recharts

**Spec:** `docs/superpowers/specs/2026-03-26-phase3-audit-dashboard-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `cogniwall/audit.py` | Create | AuditClient — queue, flush, HTTP posting |
| `cogniwall/guard.py` | Modify | Accept `audit` param, call `record()` after evaluate |
| `cogniwall/config.py` | Modify | Parse `audit:` YAML section |
| `cogniwall/__init__.py` | Modify | Export `AuditClient` |
| `cogniwall.yaml` | Modify | Add commented audit example |
| `tests/test_audit.py` | Create | AuditClient unit tests |
| `tests/test_guard.py` | Modify | Audit integration tests |
| `tests/test_config.py` | Modify | Audit config parsing tests |
| `dashboard/package.json` | Create | Next.js project dependencies |
| `dashboard/next.config.js` | Create | Next.js config |
| `dashboard/.env.example` | Create | Environment variables template |
| `dashboard/docker-compose.yml` | Create | PostgreSQL + dashboard |
| `dashboard/prisma/schema.prisma` | Create | Database schema |
| `dashboard/src/app/layout.tsx` | Create | Root layout with sidebar |
| `dashboard/src/app/page.tsx` | Create | Event log (main page) |
| `dashboard/src/app/events/[id]/page.tsx` | Create | Event drill-down |
| `dashboard/src/app/analytics/page.tsx` | Create | Analytics charts |
| `dashboard/src/app/api/events/route.ts` | Create | POST + GET events |
| `dashboard/src/app/api/analytics/route.ts` | Create | GET analytics |
| `dashboard/src/lib/prisma.ts` | Create | Prisma client singleton |
| `dashboard/src/lib/queries.ts` | Create | Database query helpers |
| `dashboard/src/lib/validation.ts` | Create | Event schema validation |
| `dashboard/src/components/sidebar.tsx` | Create | Navigation sidebar |
| `dashboard/src/components/event-table.tsx` | Create | Event log table |
| `dashboard/src/components/event-filters.tsx` | Create | Filter bar |
| `dashboard/src/components/event-detail.tsx` | Create | Drill-down view |
| `dashboard/src/components/payload-viewer.tsx` | Create | Collapsible JSON tree |
| `dashboard/src/components/analytics-cards.tsx` | Create | Summary metric cards |
| `dashboard/src/components/charts/evaluations-chart.tsx` | Create | Area chart |
| `dashboard/src/components/charts/top-rules-chart.tsx` | Create | Bar chart |
| `dashboard/src/components/charts/top-agents-chart.tsx` | Create | Bar chart |

---

### Task 1: AuditClient Core

**Files:**
- Create: `cogniwall/audit.py`
- Create: `tests/test_audit.py`

- [ ] **Step 1: Write the failing tests for AuditClient**

`tests/test_audit.py`:
```python
import asyncio
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import patch, MagicMock

import pytest

from cogniwall.audit import AuditClient


class TestAuditClientRecord:
    def test_record_enqueues_event(self):
        client = AuditClient(endpoint="http://localhost:9999/api/events")
        event = {"event_id": "abc", "status": "approved"}
        client.record(event)
        assert len(client._queue) == 1
        assert client._queue[0] == event

    def test_record_drops_oldest_when_full(self):
        client = AuditClient(
            endpoint="http://localhost:9999/api/events",
            max_queue_size=2,
        )
        client.record({"event_id": "1"})
        client.record({"event_id": "2"})
        client.record({"event_id": "3"})
        assert len(client._queue) == 2
        assert client._queue[0]["event_id"] == "2"
        assert client._queue[1]["event_id"] == "3"


class TestAuditClientFlush:
    def test_flush_sends_batch(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                body = json.loads(self.rfile.read(length))
                received.extend(body)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"accepted": 2}')

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = Thread(target=server.handle_request, daemon=True)
        thread.start()

        client = AuditClient(
            endpoint=f"http://127.0.0.1:{port}/api/events",
            flush_mode="async",
            batch_size=10,
        )
        client.record({"event_id": "a", "status": "approved"})
        client.record({"event_id": "b", "status": "blocked"})
        client._flush_sync()

        thread.join(timeout=5)
        server.server_close()
        assert len(received) == 2
        assert received[0]["event_id"] == "a"
        assert len(client._queue) == 0

    def test_flush_respects_batch_size(self):
        client = AuditClient(
            endpoint="http://localhost:9999/api/events",
            batch_size=2,
        )
        for i in range(5):
            client.record({"event_id": str(i)})

        with patch.object(client, "_post") as mock_post:
            mock_post.return_value = True
            client._flush_sync()

        # Should send batch_size=2 events, leaving 3
        assert mock_post.call_count == 1
        sent = json.loads(mock_post.call_args[0][0])
        assert len(sent) == 2
        assert len(client._queue) == 3


class TestAuditClientSyncMode:
    def test_sync_mode_posts_immediately(self):
        client = AuditClient(
            endpoint="http://localhost:9999/api/events",
            flush_mode="sync",
        )
        with patch.object(client, "_post") as mock_post:
            mock_post.return_value = True
            client.record({"event_id": "x", "status": "blocked"})

        mock_post.assert_called_once()
        assert len(client._queue) == 0


class TestAuditClientApiKey:
    def test_api_key_sent_in_header(self):
        received_headers = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received_headers["X-CogniWall-Key"] = self.headers.get("X-CogniWall-Key")
                length = int(self.headers["Content-Length"])
                self.rfile.read(length)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"accepted": 1}')

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = Thread(target=server.handle_request, daemon=True)
        thread.start()

        client = AuditClient(
            endpoint=f"http://127.0.0.1:{port}/api/events",
            api_key="test-key-123",
        )
        client.record({"event_id": "a"})
        client._flush_sync()

        thread.join(timeout=5)
        server.server_close()
        assert received_headers["X-CogniWall-Key"] == "test-key-123"


class TestAuditClientFailureHandling:
    def test_failed_post_logs_warning(self, caplog):
        client = AuditClient(endpoint="http://127.0.0.1:1/api/events")
        client.record({"event_id": "a"})
        with caplog.at_level(logging.WARNING, logger="cogniwall.audit"):
            client._flush_sync()
        assert len(client._queue) == 0  # events are discarded, not re-queued
        assert "audit" in caplog.text.lower() or len(caplog.records) > 0

    def test_failed_sync_post_does_not_raise(self):
        client = AuditClient(
            endpoint="http://127.0.0.1:1/api/events",
            flush_mode="sync",
        )
        # Should not raise — failure is silently logged
        client.record({"event_id": "a"})


class TestAuditClientFromConfig:
    def test_from_config_all_params(self):
        client = AuditClient.from_config({
            "endpoint": "http://localhost:3000/api/events",
            "api_key": "my-key",
            "include_payload": True,
            "flush_mode": "sync",
            "flush_interval": 10.0,
            "batch_size": 100,
        })
        assert client.endpoint == "http://localhost:3000/api/events"
        assert client.api_key == "my-key"
        assert client.include_payload is True
        assert client.flush_mode == "sync"
        assert client.flush_interval == 10.0
        assert client.batch_size == 100

    def test_from_config_defaults(self):
        client = AuditClient.from_config({
            "endpoint": "http://localhost:3000/api/events",
        })
        assert client.api_key is None
        assert client.include_payload is False
        assert client.flush_mode == "async"
        assert client.flush_interval == 5.0
        assert client.batch_size == 50

    def test_from_config_api_key_env(self):
        with patch.dict("os.environ", {"MY_KEY": "env-key-value"}):
            client = AuditClient.from_config({
                "endpoint": "http://localhost:3000/api/events",
                "api_key_env": "MY_KEY",
            })
        assert client.api_key == "env-key-value"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_audit.py -v`
Expected: FAIL — `ImportError: cannot import name 'AuditClient'`

- [ ] **Step 3: Implement AuditClient**

`cogniwall/audit.py`:
```python
from __future__ import annotations

import json
import logging
import os
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger("cogniwall.audit")


class AuditClient:
    """Non-blocking audit event client that sends events to a dashboard."""

    def __init__(
        self,
        endpoint: str,
        api_key: str | None = None,
        include_payload: bool = False,
        flush_mode: str = "async",
        flush_interval: float = 5.0,
        batch_size: int = 50,
        max_queue_size: int = 10_000,
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.include_payload = include_payload
        self.flush_mode = flush_mode
        self.flush_interval = flush_interval
        self.batch_size = batch_size
        self._queue: deque[dict[str, Any]] = deque(maxlen=max_queue_size)
        self._flush_task = None

    def record(self, event: dict[str, Any]) -> None:
        """Record an audit event. In sync mode, POST immediately. In async mode, enqueue."""
        if self.flush_mode == "sync":
            try:
                self._post(json.dumps([event]))
            except Exception:
                logger.warning("Failed to send audit event (sync mode)", exc_info=True)
            return
        self._queue.append(event)

    def build_event(
        self,
        verdict: Any,
        payload: dict | None = None,
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        """Build an AuditEvent dict from a Verdict."""
        event: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": verdict.status,
            "rule": verdict.rule,
            "reason": verdict.reason,
            "details": verdict.details,
            "elapsed_ms": verdict.elapsed_ms,
            "payload": payload if self.include_payload else None,
            "metadata": metadata,
        }
        return event

    def _flush_sync(self) -> None:
        """Flush up to batch_size events synchronously."""
        if not self._queue:
            return
        batch = []
        for _ in range(min(self.batch_size, len(self._queue))):
            batch.append(self._queue.popleft())
        try:
            self._post(json.dumps(batch, default=str))
        except Exception:
            logger.warning(
                "Failed to flush %d audit events", len(batch), exc_info=True
            )

    async def flush_async(self) -> None:
        """Flush events in a background loop."""
        import asyncio

        while True:
            await asyncio.sleep(self.flush_interval)
            self._flush_sync()

    async def start(self) -> None:
        """Start the background flush loop."""
        import asyncio

        if self._flush_task is None and self.flush_mode == "async":
            self._flush_task = asyncio.create_task(self.flush_async())

    async def stop(self) -> None:
        """Stop the background flush loop and flush remaining events."""
        if self._flush_task is not None:
            self._flush_task.cancel()
            self._flush_task = None
        # Final flush
        while self._queue:
            self._flush_sync()

    def _post(self, body: str) -> bool:
        """POST a JSON body to the endpoint. Returns True on success."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-CogniWall-Key"] = self.api_key
        req = Request(
            self.endpoint,
            data=body.encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (URLError, OSError) as e:
            logger.warning("Audit POST failed: %s", e)
            raise

    @classmethod
    def from_config(cls, config: dict) -> AuditClient:
        """Create an AuditClient from a config dict (parsed from YAML)."""
        api_key = config.get("api_key")
        if not api_key and "api_key_env" in config:
            api_key = os.environ.get(config["api_key_env"])
        return cls(
            endpoint=config["endpoint"],
            api_key=api_key,
            include_payload=config.get("include_payload", False),
            flush_mode=config.get("flush_mode", "async"),
            flush_interval=config.get("flush_interval", 5.0),
            batch_size=config.get("batch_size", 50),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_audit.py -v`
Expected: all passed

- [ ] **Step 5: Run full suite to verify no regressions**

Run: `.venv/bin/pytest tests/ -v --ignore=tests/test_adversarial.py --ignore=tests/test_adversarial_r2.py --ignore=tests/test_adversarial_r3.py`
Expected: all passed

- [ ] **Step 6: Commit**

```bash
git add cogniwall/audit.py tests/test_audit.py
git commit -m "feat: add AuditClient for non-blocking event capture"
```

---

### Task 2: Guard Integration

**Files:**
- Modify: `cogniwall/guard.py`
- Modify: `tests/test_guard.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_guard.py`:
```python
from unittest.mock import MagicMock, patch
from cogniwall.audit import AuditClient


class TestCogniWallWithAudit:
    @pytest.mark.asyncio
    async def test_audit_record_called_on_evaluate(self):
        audit = MagicMock(spec=AuditClient)
        audit.include_payload = False
        audit.build_event = MagicMock(return_value={"event_id": "test"})
        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            audit=audit,
        )
        verdict = await guard.evaluate_async({"body": "Hello"})
        assert not verdict.blocked
        audit.build_event.assert_called_once()
        audit.record.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_receives_metadata(self):
        audit = MagicMock(spec=AuditClient)
        audit.include_payload = False
        audit.build_event = MagicMock(return_value={"event_id": "test"})
        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            audit=audit,
        )
        await guard.evaluate_async(
            {"body": "Hello"},
            metadata={"agent_id": "bot-1"},
        )
        call_kwargs = audit.build_event.call_args
        assert call_kwargs[1]["metadata"] == {"agent_id": "bot-1"}

    @pytest.mark.asyncio
    async def test_audit_includes_payload_when_configured(self):
        audit = MagicMock(spec=AuditClient)
        audit.include_payload = True
        audit.build_event = MagicMock(return_value={"event_id": "test"})
        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            audit=audit,
        )
        payload = {"body": "Hello"}
        await guard.evaluate_async(payload)
        call_kwargs = audit.build_event.call_args
        assert call_kwargs[1]["payload"] == payload

    @pytest.mark.asyncio
    async def test_audit_failure_does_not_affect_verdict(self):
        audit = MagicMock(spec=AuditClient)
        audit.include_payload = False
        audit.build_event = MagicMock(side_effect=RuntimeError("audit broke"))
        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            audit=audit,
        )
        verdict = await guard.evaluate_async({"body": "Hello"})
        assert not verdict.blocked  # verdict still correct

    @pytest.mark.asyncio
    async def test_no_audit_backward_compatible(self):
        guard = CogniWall(rules=[PiiDetectionRule(block=["ssn"])])
        verdict = await guard.evaluate_async({"body": "Hello"})
        assert not verdict.blocked

    def test_evaluate_sync_with_metadata(self):
        audit = MagicMock(spec=AuditClient)
        audit.include_payload = False
        audit.build_event = MagicMock(return_value={"event_id": "test"})
        guard = CogniWall(
            rules=[PiiDetectionRule(block=["ssn"])],
            audit=audit,
        )
        verdict = guard.evaluate({"body": "Hello"}, metadata={"agent_id": "bot-1"})
        assert not verdict.blocked
        audit.build_event.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_guard.py::TestCogniWallWithAudit -v`
Expected: FAIL — `TypeError: CogniWall.__init__() got an unexpected keyword argument 'audit'`

- [ ] **Step 3: Modify guard.py**

Replace the full content of `cogniwall/guard.py`:
```python
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Literal, TYPE_CHECKING

from cogniwall.config import load_config
from cogniwall.pipeline import Pipeline
from cogniwall.rules.base import Rule
from cogniwall.verdict import Verdict

if TYPE_CHECKING:
    from cogniwall.audit import AuditClient

logger = logging.getLogger("cogniwall.audit")


class CogniWall:
    def __init__(
        self,
        rules: list[Rule],
        on_error: Literal["error", "block", "approve"] = "error",
        audit: AuditClient | None = None,
    ):
        self._pipeline = Pipeline(rules=rules, on_error=on_error)
        self._audit = audit

    @classmethod
    def from_yaml(
        cls,
        path: str | Path,
        audit: AuditClient | None = None,
    ) -> CogniWall:
        config = load_config(path)
        resolved_audit = audit or config.get("audit")
        return cls(
            rules=config["rules"],
            on_error=config["on_error"],
            audit=resolved_audit,
        )

    async def evaluate_async(
        self,
        payload: dict,
        metadata: dict | None = None,
    ) -> Verdict:
        if not isinstance(payload, dict):
            raise TypeError(f"Payload must be a dict, got {type(payload).__name__}")
        verdict = await self._pipeline.run(payload)
        self._try_audit(verdict, payload, metadata)
        return verdict

    def evaluate(
        self,
        payload: dict,
        metadata: dict | None = None,
    ) -> Verdict:
        if not isinstance(payload, dict):
            raise TypeError(f"Payload must be a dict, got {type(payload).__name__}")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                verdict = pool.submit(
                    asyncio.run, self._pipeline.run(payload)
                ).result()
        else:
            verdict = asyncio.run(self._pipeline.run(payload))
        self._try_audit(verdict, payload, metadata)
        return verdict

    def _try_audit(
        self,
        verdict: Verdict,
        payload: dict,
        metadata: dict | None,
    ) -> None:
        """Attempt to record an audit event. Never raises."""
        if self._audit is None:
            return
        try:
            event = self._audit.build_event(
                verdict=verdict,
                payload=payload if self._audit.include_payload else None,
                metadata=metadata,
            )
            self._audit.record(event)
        except Exception:
            logger.warning("Failed to record audit event", exc_info=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_guard.py -v`
Expected: all passed (both old and new tests)

- [ ] **Step 5: Run full suite**

Run: `.venv/bin/pytest tests/ -v --ignore=tests/test_adversarial.py --ignore=tests/test_adversarial_r2.py --ignore=tests/test_adversarial_r3.py`
Expected: all passed

- [ ] **Step 6: Commit**

```bash
git add cogniwall/guard.py tests/test_guard.py
git commit -m "feat: integrate AuditClient into CogniWall guard"
```

---

### Task 3: Config Integration

**Files:**
- Modify: `cogniwall/config.py`
- Modify: `tests/test_config.py`
- Modify: `cogniwall.yaml`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_config.py`:
```python
from cogniwall.audit import AuditClient


class TestAuditConfigParsing:
    def test_parse_config_with_audit(self):
        from cogniwall.config import parse_config
        result = parse_config({
            "version": "1",
            "rules": [],
            "audit": {
                "endpoint": "http://localhost:3000/api/events",
                "include_payload": True,
                "flush_mode": "sync",
            },
        })
        assert isinstance(result["audit"], AuditClient)
        assert result["audit"].endpoint == "http://localhost:3000/api/events"
        assert result["audit"].include_payload is True
        assert result["audit"].flush_mode == "sync"

    def test_parse_config_without_audit(self):
        from cogniwall.config import parse_config
        result = parse_config({"version": "1", "rules": []})
        assert result["audit"] is None

    def test_audit_missing_endpoint(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="endpoint"):
            parse_config({
                "version": "1",
                "rules": [],
                "audit": {"include_payload": True},
            })

    def test_audit_invalid_flush_mode(self):
        from cogniwall.config import parse_config
        with pytest.raises(CogniWallConfigError, match="flush_mode"):
            parse_config({
                "version": "1",
                "rules": [],
                "audit": {
                    "endpoint": "http://localhost:3000/api/events",
                    "flush_mode": "invalid",
                },
            })
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_config.py::TestAuditConfigParsing -v`
Expected: FAIL — `KeyError: 'audit'`

- [ ] **Step 3: Modify config.py**

Add at the top of `cogniwall/config.py`, after the existing imports:
```python
from cogniwall.audit import AuditClient
```

At the end of `parse_config()`, before the return statement, add audit parsing:
```python
    # Parse audit config
    audit = None
    raw_audit = raw.get("audit")
    if raw_audit:
        _validate_audit_config(raw_audit)
        audit = AuditClient.from_config(raw_audit)

    return {"rules": rules, "on_error": on_error, "audit": audit}
```

And update the existing return statement (remove the old one).

Add the validation function at the end of `config.py`:
```python
def _validate_audit_config(config: dict) -> None:
    """Validate the audit configuration section."""
    if "endpoint" not in config:
        raise CogniWallConfigError(
            "audit config requires 'endpoint' parameter"
        )
    flush_mode = config.get("flush_mode", "async")
    if flush_mode not in ("async", "sync"):
        raise CogniWallConfigError(
            f"audit 'flush_mode' must be 'async' or 'sync', got '{flush_mode}'"
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: all passed

- [ ] **Step 5: Update cogniwall.yaml with audit example**

Add at the end of `cogniwall.yaml`:
```yaml

# Audit Dashboard — send evaluation events to a dashboard
# Start the dashboard: cd dashboard && npm run dev
# audit:
#   endpoint: http://localhost:3000/api/events
#   # api_key_env: COGNIWALL_AUDIT_KEY
#   # include_payload: false
#   # flush_mode: async
#   # flush_interval: 5.0
#   # batch_size: 50
```

- [ ] **Step 6: Run full suite**

Run: `.venv/bin/pytest tests/ -v --ignore=tests/test_adversarial.py --ignore=tests/test_adversarial_r2.py --ignore=tests/test_adversarial_r3.py`
Expected: all passed

- [ ] **Step 7: Commit**

```bash
git add cogniwall/config.py tests/test_config.py cogniwall.yaml
git commit -m "feat: add audit config parsing for YAML configuration"
```

---

### Task 4: Exports & Public API

**Files:**
- Modify: `cogniwall/__init__.py`

- [ ] **Step 1: Write the failing test**

Run in shell:
```bash
.venv/bin/python -c "from cogniwall import AuditClient; print('OK')"
```
Expected: FAIL — `ImportError: cannot import name 'AuditClient'`

- [ ] **Step 2: Update exports**

Add to `cogniwall/__init__.py`:
```python
from cogniwall.audit import AuditClient
```

Add `"AuditClient"` to the `__all__` list.

- [ ] **Step 3: Verify import works**

Run:
```bash
.venv/bin/python -c "from cogniwall import CogniWall, Verdict, AuditClient; print('All imports OK')"
```
Expected: `All imports OK`

- [ ] **Step 4: Run full suite**

Run: `.venv/bin/pytest tests/ -v --ignore=tests/test_adversarial.py --ignore=tests/test_adversarial_r2.py --ignore=tests/test_adversarial_r3.py`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add cogniwall/__init__.py
git commit -m "feat: export AuditClient from public API"
```

---

### Task 5: Dashboard Scaffold

**Files:**
- Create: `dashboard/` directory with Next.js project, Prisma schema, Docker Compose

- [ ] **Step 1: Initialize Next.js project**

```bash
cd /Users/jerry-poon/dev/cogniwall
npx create-next-app@latest dashboard --typescript --tailwind --eslint --app --src-dir --no-import-alias --use-npm
```

- [ ] **Step 2: Install dependencies**

```bash
cd dashboard
npm install prisma @prisma/client recharts
npm install -D @types/node
npx shadcn@latest init -d
npx shadcn@latest add badge button card dropdown-menu input select table separator
```

- [ ] **Step 3: Create Prisma schema**

`dashboard/prisma/schema.prisma`:
```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model AuditEvent {
  id        String   @id @default(uuid()) @db.Uuid
  eventId   String   @unique @map("event_id") @db.Uuid
  timestamp DateTime @db.Timestamptz()
  status    String
  rule      String?
  reason    String?
  details   Json?
  elapsedMs Float    @map("elapsed_ms")
  payload   Json?
  metadata  Json?
  createdAt DateTime @default(now()) @map("created_at") @db.Timestamptz()

  @@index([timestamp(sort: Desc)])
  @@index([status])
  @@index([rule])
  @@map("audit_events")
}
```

- [ ] **Step 4: Create .env.example**

`dashboard/.env.example`:
```
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cogniwall?schema=public"

# Optional: require API key for event ingestion
# COGNIWALL_API_KEY=your-api-key-here
```

- [ ] **Step 5: Create docker-compose.yml**

`dashboard/docker-compose.yml`:
```yaml
version: "3.8"

services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: cogniwall
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  dashboard:
    build: .
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: "postgresql://postgres:postgres@db:5432/cogniwall?schema=public"
    depends_on:
      - db

volumes:
  pgdata:
```

- [ ] **Step 6: Create Prisma client singleton**

`dashboard/src/lib/prisma.ts`:
```typescript
import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
```

- [ ] **Step 7: Create event validation**

`dashboard/src/lib/validation.ts`:
```typescript
export interface AuditEventInput {
  event_id: string;
  timestamp: string;
  status: "approved" | "blocked" | "error";
  rule?: string | null;
  reason?: string | null;
  details?: Record<string, unknown> | null;
  elapsed_ms: number;
  payload?: Record<string, unknown> | null;
  metadata?: Record<string, unknown> | null;
}

export interface ValidationResult {
  valid: AuditEventInput[];
  errors: { index: number; error: string }[];
}

const VALID_STATUSES = new Set(["approved", "blocked", "error"]);

export function validateEvents(events: unknown[]): ValidationResult {
  const valid: AuditEventInput[] = [];
  const errors: { index: number; error: string }[] = [];

  for (let i = 0; i < events.length; i++) {
    const event = events[i] as Record<string, unknown>;

    if (!event || typeof event !== "object") {
      errors.push({ index: i, error: "Event must be an object" });
      continue;
    }
    if (!event.event_id || typeof event.event_id !== "string") {
      errors.push({ index: i, error: "Missing or invalid event_id" });
      continue;
    }
    if (!event.timestamp || typeof event.timestamp !== "string") {
      errors.push({ index: i, error: "Missing or invalid timestamp" });
      continue;
    }
    if (!VALID_STATUSES.has(event.status as string)) {
      errors.push({ index: i, error: `Invalid status: ${event.status}` });
      continue;
    }
    if (typeof event.elapsed_ms !== "number") {
      errors.push({ index: i, error: "Missing or invalid elapsed_ms" });
      continue;
    }

    valid.push(event as unknown as AuditEventInput);
  }

  return { valid, errors };
}
```

- [ ] **Step 8: Verify the scaffold builds**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard
cp .env.example .env
npx prisma generate
npm run build
```
Expected: Build succeeds

- [ ] **Step 9: Commit**

```bash
cd /Users/jerry-poon/dev/cogniwall
git add dashboard/
git commit -m "feat: scaffold Next.js dashboard with Prisma schema and Docker Compose"
```

---

### Task 6: Event Ingestion API (POST /api/events)

**Files:**
- Create: `dashboard/src/app/api/events/route.ts`

- [ ] **Step 1: Implement POST handler**

`dashboard/src/app/api/events/route.ts`:
```typescript
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { validateEvents } from "@/lib/validation";

function checkApiKey(request: NextRequest): boolean {
  const requiredKey = process.env.COGNIWALL_API_KEY;
  if (!requiredKey) return true; // no key configured = allow all
  const providedKey = request.headers.get("X-CogniWall-Key");
  return providedKey === requiredKey;
}

export async function POST(request: NextRequest) {
  if (!checkApiKey(request)) {
    return NextResponse.json({ error: "Invalid API key" }, { status: 401 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!Array.isArray(body)) {
    return NextResponse.json(
      { error: "Body must be a JSON array of events" },
      { status: 400 }
    );
  }

  const { valid, errors } = validateEvents(body);

  let accepted = 0;
  const insertErrors: { index: number; error: string }[] = [...errors];

  if (valid.length > 0) {
    try {
      const result = await prisma.auditEvent.createMany({
        data: valid.map((e) => ({
          eventId: e.event_id,
          timestamp: new Date(e.timestamp),
          status: e.status,
          rule: e.rule ?? null,
          reason: e.reason ?? null,
          details: e.details ?? undefined,
          elapsedMs: e.elapsed_ms,
          payload: e.payload ?? undefined,
          metadata: e.metadata ?? undefined,
        })),
        skipDuplicates: true,
      });
      accepted = result.count;
    } catch (error) {
      return NextResponse.json(
        { error: "Database insert failed", detail: String(error) },
        { status: 500 }
      );
    }
  }

  return NextResponse.json({
    accepted,
    rejected: errors.length,
    errors: insertErrors,
  });
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard && npm run build
```
Expected: Build succeeds

- [ ] **Step 3: Commit**

```bash
cd /Users/jerry-poon/dev/cogniwall
git add dashboard/src/app/api/events/route.ts
git commit -m "feat: add POST /api/events endpoint for event ingestion"
```

---

### Task 7: Event List API (GET /api/events)

**Files:**
- Modify: `dashboard/src/app/api/events/route.ts`
- Create: `dashboard/src/lib/queries.ts`

- [ ] **Step 1: Create query helpers**

`dashboard/src/lib/queries.ts`:
```typescript
import { prisma } from "@/lib/prisma";
import { Prisma } from "@prisma/client";

export interface EventListParams {
  status?: string;
  rule?: string;
  from?: string;
  to?: string;
  search?: string;
  page?: number;
  limit?: number;
  eventId?: string;
}

export async function queryEvents(params: EventListParams) {
  const { status, rule, from, to, search, page = 1, limit = 50, eventId } = params;

  // Single event drill-down
  if (eventId) {
    const event = await prisma.auditEvent.findUnique({
      where: { eventId },
    });
    return event ? { events: [event], total: 1, page: 1, pages: 1 } : { events: [], total: 0, page: 1, pages: 0 };
  }

  const where: Prisma.AuditEventWhereInput = {};

  if (status) where.status = status;
  if (rule) where.rule = rule;
  if (from || to) {
    where.timestamp = {};
    if (from) where.timestamp.gte = new Date(from);
    if (to) where.timestamp.lte = new Date(to);
  }
  if (search) {
    where.OR = [
      { reason: { contains: search, mode: "insensitive" } },
      { rule: { contains: search, mode: "insensitive" } },
    ];
  }

  const skip = (page - 1) * limit;
  const [events, total] = await Promise.all([
    prisma.auditEvent.findMany({
      where,
      orderBy: { timestamp: "desc" },
      skip,
      take: limit,
    }),
    prisma.auditEvent.count({ where }),
  ]);

  return {
    events,
    total,
    page,
    pages: Math.ceil(total / limit),
  };
}

export async function queryAnalytics(params: {
  from?: string;
  to?: string;
  interval?: "hour" | "day" | "week";
}) {
  const now = new Date();
  const fromDate = params.from ? new Date(params.from) : new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const toDate = params.to ? new Date(params.to) : now;
  const interval = params.interval || "hour";

  const truncFn = interval === "hour"
    ? "date_trunc('hour', timestamp)"
    : interval === "day"
    ? "date_trunc('day', timestamp)"
    : "date_trunc('week', timestamp)";

  const [summary, overTime, topRules, topAgents] = await Promise.all([
    // Summary counts
    prisma.auditEvent.groupBy({
      by: ["status"],
      where: { timestamp: { gte: fromDate, lte: toDate } },
      _count: true,
    }),

    // Over time buckets
    prisma.$queryRawUnsafe<{ bucket: Date; status: string; count: bigint }[]>(
      `SELECT ${truncFn} as bucket, status, COUNT(*) as count
       FROM audit_events
       WHERE timestamp >= $1 AND timestamp <= $2
       GROUP BY bucket, status
       ORDER BY bucket ASC`,
      fromDate,
      toDate
    ),

    // Top rules
    prisma.auditEvent.groupBy({
      by: ["rule"],
      where: {
        timestamp: { gte: fromDate, lte: toDate },
        status: "blocked",
        rule: { not: null },
      },
      _count: true,
      orderBy: { _count: { rule: "desc" } },
      take: 10,
    }),

    // Top blocked agents
    prisma.$queryRawUnsafe<{ agent_id: string; count: bigint }[]>(
      `SELECT metadata->>'agent_id' as agent_id, COUNT(*) as count
       FROM audit_events
       WHERE timestamp >= $1 AND timestamp <= $2
         AND status = 'blocked'
         AND metadata->>'agent_id' IS NOT NULL
       GROUP BY metadata->>'agent_id'
       ORDER BY count DESC
       LIMIT 10`,
      fromDate,
      toDate
    ),
  ]);

  // Format summary
  const counts: Record<string, number> = { approved: 0, blocked: 0, error: 0 };
  for (const row of summary) {
    counts[row.status] = row._count;
  }
  const total = counts.approved + counts.blocked + counts.error;

  // Format over-time into bucketed rows
  const bucketMap = new Map<string, { approved: number; blocked: number; errors: number }>();
  for (const row of overTime) {
    const key = row.bucket.toISOString();
    if (!bucketMap.has(key)) {
      bucketMap.set(key, { approved: 0, blocked: 0, errors: 0 });
    }
    const bucket = bucketMap.get(key)!;
    if (row.status === "approved") bucket.approved = Number(row.count);
    else if (row.status === "blocked") bucket.blocked = Number(row.count);
    else if (row.status === "error") bucket.errors = Number(row.count);
  }
  const over_time = Array.from(bucketMap.entries()).map(([bucket, data]) => ({
    bucket,
    ...data,
  }));

  return {
    summary: {
      total,
      approved: counts.approved,
      blocked: counts.blocked,
      errors: counts.error,
      block_rate: total > 0 ? counts.blocked / total : 0,
    },
    over_time,
    top_rules: topRules.map((r) => ({ rule: r.rule, count: r._count })),
    top_blocked_agents: topAgents.map((a) => ({
      agent_id: a.agent_id,
      blocked_count: Number(a.count),
    })),
  };
}
```

- [ ] **Step 2: Add GET handler to events route**

Add to `dashboard/src/app/api/events/route.ts`:
```typescript
import { queryEvents } from "@/lib/queries";

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;

  const result = await queryEvents({
    status: params.get("status") || undefined,
    rule: params.get("rule") || undefined,
    from: params.get("from") || undefined,
    to: params.get("to") || undefined,
    search: params.get("search") || undefined,
    page: params.has("page") ? Number(params.get("page")) : undefined,
    limit: params.has("limit") ? Number(params.get("limit")) : undefined,
    eventId: params.get("event_id") || undefined,
  });

  return NextResponse.json(result);
}
```

- [ ] **Step 3: Verify it compiles**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard && npm run build
```

- [ ] **Step 4: Commit**

```bash
cd /Users/jerry-poon/dev/cogniwall
git add dashboard/src/app/api/events/route.ts dashboard/src/lib/queries.ts
git commit -m "feat: add GET /api/events with filtering, pagination, and drill-down"
```

---

### Task 8: Analytics API (GET /api/analytics)

**Files:**
- Create: `dashboard/src/app/api/analytics/route.ts`

- [ ] **Step 1: Implement analytics endpoint**

`dashboard/src/app/api/analytics/route.ts`:
```typescript
import { NextRequest, NextResponse } from "next/server";
import { queryAnalytics } from "@/lib/queries";

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;

  const interval = params.get("interval") as "hour" | "day" | "week" | null;

  const result = await queryAnalytics({
    from: params.get("from") || undefined,
    to: params.get("to") || undefined,
    interval: interval || undefined,
  });

  return NextResponse.json(result);
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard && npm run build
```

- [ ] **Step 3: Commit**

```bash
cd /Users/jerry-poon/dev/cogniwall
git add dashboard/src/app/api/analytics/route.ts
git commit -m "feat: add GET /api/analytics endpoint with summary and time-series"
```

---

### Task 9: Dashboard Layout & Sidebar

**Files:**
- Modify: `dashboard/src/app/layout.tsx`
- Create: `dashboard/src/components/sidebar.tsx`

- [ ] **Step 1: Create sidebar component**

`dashboard/src/components/sidebar.tsx`:
```tsx
"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/", label: "Events", icon: "📋" },
  { href: "/analytics", label: "Analytics", icon: "📊" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 min-h-screen bg-zinc-900 border-r border-zinc-800 flex flex-col">
      <div className="p-6 border-b border-zinc-800">
        <h1 className="text-xl font-bold text-white">CogniWall</h1>
        <p className="text-xs text-zinc-500 mt-1">Audit Dashboard</p>
      </div>
      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/" || pathname.startsWith("/events")
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                isActive
                  ? "bg-zinc-800 text-white"
                  : "text-zinc-400 hover:text-white hover:bg-zinc-800/50"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="p-4 border-t border-zinc-800">
        <p className="text-xs text-zinc-600">v0.1.0</p>
      </div>
    </aside>
  );
}
```

- [ ] **Step 2: Update root layout**

Replace `dashboard/src/app/layout.tsx`:
```tsx
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "CogniWall Audit Dashboard",
  description: "Monitor and analyze AI agent guardrail evaluations",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-zinc-950 text-zinc-100`}>
        <div className="flex min-h-screen">
          <Sidebar />
          <main className="flex-1 p-8">{children}</main>
        </div>
      </body>
    </html>
  );
}
```

- [ ] **Step 3: Verify it compiles**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard && npm run build
```

- [ ] **Step 4: Commit**

```bash
cd /Users/jerry-poon/dev/cogniwall
git add dashboard/src/components/sidebar.tsx dashboard/src/app/layout.tsx
git commit -m "feat: add dashboard layout with navigation sidebar"
```

---

### Task 10: Event Log Page

**Files:**
- Modify: `dashboard/src/app/page.tsx`
- Create: `dashboard/src/components/event-table.tsx`
- Create: `dashboard/src/components/event-filters.tsx`

- [ ] **Step 1: Create event filters component**

`dashboard/src/components/event-filters.tsx`:
```tsx
"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback } from "react";

const STATUSES = ["all", "approved", "blocked", "error"];
const RULES = [
  "all",
  "pii_detection",
  "financial_limit",
  "prompt_injection",
  "tone_sentiment",
  "rate_limit",
];

export function EventFilters() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const updateParam = useCallback(
    (key: string, value: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (value === "all" || value === "") {
        params.delete(key);
      } else {
        params.set(key, value);
      }
      params.set("page", "1");
      router.push(`/?${params.toString()}`);
    },
    [router, searchParams]
  );

  return (
    <div className="flex gap-3 mb-6">
      <select
        className="bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-300"
        value={searchParams.get("status") || "all"}
        onChange={(e) => updateParam("status", e.target.value)}
      >
        {STATUSES.map((s) => (
          <option key={s} value={s}>
            {s === "all" ? "All Statuses" : s.charAt(0).toUpperCase() + s.slice(1)}
          </option>
        ))}
      </select>

      <select
        className="bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-300"
        value={searchParams.get("rule") || "all"}
        onChange={(e) => updateParam("rule", e.target.value)}
      >
        {RULES.map((r) => (
          <option key={r} value={r}>
            {r === "all" ? "All Rules" : r}
          </option>
        ))}
      </select>

      <input
        type="text"
        placeholder="Search by reason, rule, or details..."
        className="bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-300 flex-1"
        defaultValue={searchParams.get("search") || ""}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            updateParam("search", (e.target as HTMLInputElement).value);
          }
        }}
      />
    </div>
  );
}
```

- [ ] **Step 2: Create event table component**

`dashboard/src/components/event-table.tsx`:
```tsx
import Link from "next/link";

interface AuditEvent {
  id: string;
  eventId: string;
  timestamp: string;
  status: string;
  rule: string | null;
  reason: string | null;
  elapsedMs: number;
  metadata: Record<string, unknown> | null;
}

const statusColors: Record<string, string> = {
  approved: "bg-emerald-500/20 text-emerald-400",
  blocked: "bg-red-500/20 text-red-400",
  error: "bg-amber-500/20 text-amber-400",
};

export function EventTable({
  events,
  total,
  page,
  pages,
}: {
  events: AuditEvent[];
  total: number;
  page: number;
  pages: number;
}) {
  return (
    <div>
      <div className="border border-zinc-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-zinc-900">
            <tr>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Timestamp</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Status</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Rule</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Reason</th>
              <th className="text-left px-4 py-3 text-zinc-400 font-medium">Agent</th>
              <th className="text-right px-4 py-3 text-zinc-400 font-medium">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {events.map((event) => (
              <tr
                key={event.id}
                className="hover:bg-zinc-900/50 transition-colors"
              >
                <td className="px-4 py-3 font-mono text-xs text-zinc-400">
                  <Link href={`/events/${event.eventId}`} className="hover:text-white">
                    {new Date(event.timestamp).toLocaleString()}
                  </Link>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`px-2 py-1 rounded text-xs font-medium ${statusColors[event.status] || ""}`}
                  >
                    {event.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-zinc-300">{event.rule || "—"}</td>
                <td className="px-4 py-3 text-zinc-400 max-w-xs truncate">
                  {event.reason || "—"}
                </td>
                <td className="px-4 py-3 text-zinc-400 font-mono text-xs">
                  {(event.metadata as Record<string, string>)?.agent_id || "—"}
                </td>
                <td className="px-4 py-3 text-right text-zinc-400 font-mono text-xs">
                  {event.elapsedMs.toFixed(1)}ms
                </td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-12 text-center text-zinc-500">
                  No events found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="flex justify-between items-center mt-4 text-sm text-zinc-500">
        <span>
          Page {page} of {pages} — {total.toLocaleString()} events
        </span>
        <div className="flex gap-2">
          {page > 1 && (
            <Link
              href={`?page=${page - 1}`}
              className="px-3 py-1 rounded bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
            >
              Previous
            </Link>
          )}
          {page < pages && (
            <Link
              href={`?page=${page + 1}`}
              className="px-3 py-1 rounded bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
            >
              Next
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Create the event log page**

Replace `dashboard/src/app/page.tsx`:
```tsx
import { Suspense } from "react";
import { EventFilters } from "@/components/event-filters";
import { EventTable } from "@/components/event-table";
import { queryEvents } from "@/lib/queries";

export default async function EventLogPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const params = await searchParams;
  const result = await queryEvents({
    status: params.status,
    rule: params.rule,
    from: params.from,
    to: params.to,
    search: params.search,
    page: params.page ? Number(params.page) : 1,
    limit: 50,
  });

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Events</h2>
      <Suspense fallback={<div>Loading filters...</div>}>
        <EventFilters />
      </Suspense>
      <EventTable
        events={result.events as any}
        total={result.total}
        page={result.page}
        pages={result.pages}
      />
    </div>
  );
}
```

- [ ] **Step 4: Verify it compiles**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard && npm run build
```

- [ ] **Step 5: Commit**

```bash
cd /Users/jerry-poon/dev/cogniwall
git add dashboard/src/app/page.tsx dashboard/src/components/event-table.tsx dashboard/src/components/event-filters.tsx
git commit -m "feat: add event log page with table, filters, and pagination"
```

---

### Task 11: Event Drill-down Page

**Files:**
- Create: `dashboard/src/app/events/[id]/page.tsx`
- Create: `dashboard/src/components/event-detail.tsx`
- Create: `dashboard/src/components/payload-viewer.tsx`

- [ ] **Step 1: Create payload viewer**

`dashboard/src/components/payload-viewer.tsx`:
```tsx
"use client";

import { useState } from "react";

export function PayloadViewer({ payload }: { payload: unknown }) {
  const [expanded, setExpanded] = useState(true);

  if (!payload) {
    return (
      <div className="text-sm text-zinc-500 italic p-4 bg-zinc-900 rounded-lg border border-zinc-800">
        Payload not captured. Enable <code className="text-zinc-400">include_payload</code> to
        store payloads.
      </div>
    );
  }

  return (
    <div className="bg-zinc-900 rounded-lg border border-zinc-800">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 text-left text-sm font-medium text-zinc-300 hover:bg-zinc-800/50 flex justify-between items-center"
      >
        <span>Payload</span>
        <span className="text-zinc-500">{expanded ? "▼" : "▶"}</span>
      </button>
      {expanded && (
        <pre className="px-4 pb-4 text-xs font-mono text-zinc-400 overflow-x-auto">
          {JSON.stringify(payload, null, 2)}
        </pre>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Create event detail component**

`dashboard/src/components/event-detail.tsx`:
```tsx
import { PayloadViewer } from "./payload-viewer";

const statusColors: Record<string, string> = {
  approved: "bg-emerald-500/20 text-emerald-400",
  blocked: "bg-red-500/20 text-red-400",
  error: "bg-amber-500/20 text-amber-400",
};

interface EventDetailProps {
  event: {
    eventId: string;
    timestamp: string;
    status: string;
    rule: string | null;
    reason: string | null;
    details: Record<string, unknown> | null;
    elapsedMs: number;
    payload: unknown;
    metadata: Record<string, unknown> | null;
  };
}

export function EventDetail({ event }: EventDetailProps) {
  return (
    <div className="space-y-6">
      {/* Summary Card */}
      <div className="bg-zinc-900 rounded-lg border border-zinc-800 p-6">
        <div className="flex items-center gap-4 mb-4">
          <span
            className={`px-3 py-1.5 rounded text-sm font-bold ${statusColors[event.status] || ""}`}
          >
            {event.status.toUpperCase()}
          </span>
          <span className="font-mono text-sm text-zinc-500">{event.eventId}</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-zinc-500">Timestamp</p>
            <p className="font-mono text-zinc-300">
              {new Date(event.timestamp).toLocaleString()}
            </p>
          </div>
          <div>
            <p className="text-zinc-500">Rule</p>
            <p className="text-zinc-300">{event.rule || "—"}</p>
          </div>
          <div>
            <p className="text-zinc-500">Latency</p>
            <p className="font-mono text-zinc-300">{event.elapsedMs.toFixed(1)}ms</p>
          </div>
          <div>
            <p className="text-zinc-500">Agent</p>
            <p className="font-mono text-zinc-300">
              {(event.metadata as Record<string, string>)?.agent_id || "—"}
            </p>
          </div>
        </div>
      </div>

      {/* Block Reason */}
      {event.reason && (
        <div className="bg-zinc-900 rounded-lg border border-zinc-800 p-6">
          <h3 className="text-sm font-medium text-zinc-400 mb-3">Reason</h3>
          <p className="text-zinc-200 mb-4">{event.reason}</p>
          {event.details && (
            <div>
              <h4 className="text-sm font-medium text-zinc-400 mb-2">Details</h4>
              <div className="space-y-1">
                {Object.entries(event.details).map(([key, value]) => (
                  <div key={key} className="flex gap-2 text-sm">
                    <span className="text-zinc-500 font-mono">{key}:</span>
                    <span className="text-zinc-300 font-mono">
                      {JSON.stringify(value)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Payload */}
      <PayloadViewer payload={event.payload} />

      {/* Metadata */}
      {event.metadata && Object.keys(event.metadata).length > 0 && (
        <div className="bg-zinc-900 rounded-lg border border-zinc-800 p-6">
          <h3 className="text-sm font-medium text-zinc-400 mb-3">Metadata</h3>
          <div className="space-y-1">
            {Object.entries(event.metadata).map(([key, value]) => (
              <div key={key} className="flex gap-2 text-sm">
                <span className="text-zinc-500 font-mono">{key}:</span>
                <span className="text-zinc-300 font-mono">
                  {JSON.stringify(value)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Create drill-down page**

`dashboard/src/app/events/[id]/page.tsx`:
```tsx
import Link from "next/link";
import { notFound } from "next/navigation";
import { EventDetail } from "@/components/event-detail";
import { queryEvents } from "@/lib/queries";

export default async function EventDrilldownPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const result = await queryEvents({ eventId: id });

  if (result.events.length === 0) {
    notFound();
  }

  const event = result.events[0];

  return (
    <div>
      <div className="flex items-center gap-2 mb-6 text-sm text-zinc-500">
        <Link href="/" className="hover:text-white">
          Events
        </Link>
        <span>/</span>
        <span className="text-zinc-300 font-mono">{id.slice(0, 8)}...</span>
      </div>
      <EventDetail event={event as any} />
    </div>
  );
}
```

- [ ] **Step 4: Verify it compiles**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard && npm run build
```

- [ ] **Step 5: Commit**

```bash
cd /Users/jerry-poon/dev/cogniwall
git add dashboard/src/app/events/ dashboard/src/components/event-detail.tsx dashboard/src/components/payload-viewer.tsx
git commit -m "feat: add event drill-down page with payload viewer"
```

---

### Task 12: Analytics Page

**Files:**
- Create: `dashboard/src/app/analytics/page.tsx`
- Create: `dashboard/src/components/analytics-cards.tsx`
- Create: `dashboard/src/components/charts/evaluations-chart.tsx`
- Create: `dashboard/src/components/charts/top-rules-chart.tsx`
- Create: `dashboard/src/components/charts/top-agents-chart.tsx`

- [ ] **Step 1: Create analytics summary cards**

`dashboard/src/components/analytics-cards.tsx`:
```tsx
interface AnalyticsSummary {
  total: number;
  approved: number;
  blocked: number;
  errors: number;
  block_rate: number;
}

export function AnalyticsCards({ summary }: { summary: AnalyticsSummary }) {
  const cards = [
    { label: "Total Evaluations", value: summary.total.toLocaleString(), color: "text-white" },
    { label: "Block Rate", value: `${(summary.block_rate * 100).toFixed(1)}%`, color: "text-white" },
    { label: "Blocked", value: summary.blocked.toLocaleString(), color: "text-red-400" },
    { label: "Errors", value: summary.errors.toLocaleString(), color: "text-amber-400" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      {cards.map((card) => (
        <div
          key={card.label}
          className="bg-zinc-900 border border-zinc-800 rounded-lg p-5"
        >
          <p className="text-xs text-zinc-500 mb-1">{card.label}</p>
          <p className={`text-2xl font-bold ${card.color}`}>{card.value}</p>
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 2: Create evaluations over time chart**

`dashboard/src/components/charts/evaluations-chart.tsx`:
```tsx
"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface BucketData {
  bucket: string;
  approved: number;
  blocked: number;
  errors: number;
}

export function EvaluationsChart({ data }: { data: BucketData[] }) {
  const formatted = data.map((d) => ({
    ...d,
    label: new Date(d.bucket).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }),
  }));

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 mb-8">
      <h3 className="text-sm font-medium text-zinc-400 mb-4">
        Evaluations Over Time
      </h3>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={formatted}>
          <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
          <XAxis dataKey="label" tick={{ fill: "#71717a", fontSize: 11 }} />
          <YAxis tick={{ fill: "#71717a", fontSize: 11 }} />
          <Tooltip
            contentStyle={{
              backgroundColor: "#18181b",
              border: "1px solid #27272a",
              borderRadius: "8px",
            }}
          />
          <Area
            type="monotone"
            dataKey="approved"
            stackId="1"
            stroke="#10b981"
            fill="#10b98133"
          />
          <Area
            type="monotone"
            dataKey="blocked"
            stackId="1"
            stroke="#ef4444"
            fill="#ef444433"
          />
          <Area
            type="monotone"
            dataKey="errors"
            stackId="1"
            stroke="#f59e0b"
            fill="#f59e0b33"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
```

- [ ] **Step 3: Create top rules chart**

`dashboard/src/components/charts/top-rules-chart.tsx`:
```tsx
"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface RuleData {
  rule: string;
  count: number;
}

export function TopRulesChart({ data }: { data: RuleData[] }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
      <h3 className="text-sm font-medium text-zinc-400 mb-4">
        Top Triggered Rules
      </h3>
      {data.length === 0 ? (
        <p className="text-zinc-500 text-sm">No blocked events yet</p>
      ) : (
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={data} layout="vertical">
            <XAxis type="number" tick={{ fill: "#71717a", fontSize: 11 }} />
            <YAxis
              dataKey="rule"
              type="category"
              tick={{ fill: "#a1a1aa", fontSize: 11 }}
              width={130}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#18181b",
                border: "1px solid #27272a",
                borderRadius: "8px",
              }}
            />
            <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Create top agents chart**

`dashboard/src/components/charts/top-agents-chart.tsx`:
```tsx
"use client";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface AgentData {
  agent_id: string;
  blocked_count: number;
}

export function TopAgentsChart({ data }: { data: AgentData[] }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6">
      <h3 className="text-sm font-medium text-zinc-400 mb-4">
        Top Blocked Agents
      </h3>
      {data.length === 0 ? (
        <p className="text-zinc-500 text-sm">
          No agent metadata found. Pass <code className="text-zinc-400">metadata={`{"agent_id": "..."}`}</code> to evaluate().
        </p>
      ) : (
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={data} layout="vertical">
            <XAxis type="number" tick={{ fill: "#71717a", fontSize: 11 }} />
            <YAxis
              dataKey="agent_id"
              type="category"
              tick={{ fill: "#a1a1aa", fontSize: 11 }}
              width={130}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#18181b",
                border: "1px solid #27272a",
                borderRadius: "8px",
              }}
            />
            <Bar dataKey="blocked_count" fill="#ef4444" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Create the analytics page**

`dashboard/src/app/analytics/page.tsx`:
```tsx
import { AnalyticsCards } from "@/components/analytics-cards";
import { EvaluationsChart } from "@/components/charts/evaluations-chart";
import { TopRulesChart } from "@/components/charts/top-rules-chart";
import { TopAgentsChart } from "@/components/charts/top-agents-chart";
import { queryAnalytics } from "@/lib/queries";

export default async function AnalyticsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const params = await searchParams;
  const data = await queryAnalytics({
    from: params.from,
    to: params.to,
    interval: (params.interval as "hour" | "day" | "week") || "hour",
  });

  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Analytics</h2>
      <AnalyticsCards summary={data.summary} />
      <EvaluationsChart data={data.over_time} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <TopRulesChart data={data.top_rules} />
        <TopAgentsChart data={data.top_blocked_agents} />
      </div>
    </div>
  );
}
```

- [ ] **Step 6: Verify it compiles**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard && npm run build
```

- [ ] **Step 7: Commit**

```bash
cd /Users/jerry-poon/dev/cogniwall
git add dashboard/src/app/analytics/ dashboard/src/components/analytics-cards.tsx dashboard/src/components/charts/
git commit -m "feat: add analytics page with summary cards and charts"
```

---

### Task 13: End-to-End Verification

- [ ] **Step 1: Start PostgreSQL and run migrations**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard
docker compose up db -d
cp .env.example .env
npx prisma migrate dev --name init
```

- [ ] **Step 2: Start the dashboard**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard
npm run dev &
```

- [ ] **Step 3: Test event ingestion from Python**

```bash
cd /Users/jerry-poon/dev/cogniwall
.venv/bin/python -c "
from cogniwall import CogniWall, AuditClient, PiiDetectionRule

audit = AuditClient(
    endpoint='http://localhost:3000/api/events',
    include_payload=True,
    flush_mode='sync',
)
guard = CogniWall(rules=[PiiDetectionRule(block=['ssn'])], audit=audit)

# Test blocked
v1 = guard.evaluate({'body': 'SSN: 123-45-6789'}, metadata={'agent_id': 'test-bot'})
print(f'Blocked: {v1.blocked}, rule: {v1.rule}')

# Test approved
v2 = guard.evaluate({'body': 'Hello world'}, metadata={'agent_id': 'test-bot'})
print(f'Approved: {not v2.blocked}')

print('Events sent successfully!')
"
```
Expected: Two events posted, both print success.

- [ ] **Step 4: Verify events in dashboard**

Open `http://localhost:3000` in browser. Should see two events: one blocked (pii_detection), one approved.

- [ ] **Step 5: Run full Python test suite**

```bash
cd /Users/jerry-poon/dev/cogniwall
.venv/bin/pytest tests/ -v --ignore=tests/test_adversarial.py --ignore=tests/test_adversarial_r2.py --ignore=tests/test_adversarial_r3.py
```
Expected: all passed

- [ ] **Step 6: Stop services and commit**

```bash
cd /Users/jerry-poon/dev/cogniwall/dashboard
docker compose down
kill %1  # stop npm run dev
```

```bash
cd /Users/jerry-poon/dev/cogniwall
git add -A
git commit -m "feat: Phase 3 Audit Dashboard — end-to-end verified"
```
