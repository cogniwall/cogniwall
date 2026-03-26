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
