from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal

from agentguard.config import load_config
from agentguard.pipeline import Pipeline
from agentguard.rules.base import Rule
from agentguard.verdict import Verdict


class AgentGuard:
    def __init__(
        self,
        rules: list[Rule],
        on_error: Literal["error", "block", "approve"] = "error",
    ):
        self._pipeline = Pipeline(rules=rules, on_error=on_error)

    @classmethod
    def from_yaml(cls, path: str | Path) -> AgentGuard:
        config = load_config(path)
        return cls(rules=config["rules"], on_error=config["on_error"])

    async def evaluate_async(self, payload: dict) -> Verdict:
        if not isinstance(payload, dict):
            raise TypeError(f"Payload must be a dict, got {type(payload).__name__}")
        return await self._pipeline.run(payload)

    def evaluate(self, payload: dict) -> Verdict:
        if not isinstance(payload, dict):
            raise TypeError(f"Payload must be a dict, got {type(payload).__name__}")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(
                    asyncio.run, self._pipeline.run(payload)
                ).result()
        else:
            return asyncio.run(self._pipeline.run(payload))
