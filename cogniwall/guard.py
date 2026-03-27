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

logger = logging.getLogger("cogniwall.guard")


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
        if self._audit is not None:
            await self._audit.start()  # idempotent — has `if self._flush_task is None` guard
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
        # In sync path, manually flush since async loop can't run
        if self._audit is not None and self._audit.flush_mode == "async":
            try:
                self._audit._flush_sync()
            except Exception:
                logger.warning("Failed to flush audit events (sync path)", exc_info=True)
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
                payload=payload,
                metadata=metadata,
            )
            self._audit.record(event)
        except Exception:
            logger.warning("Failed to record audit event", exc_info=True)
