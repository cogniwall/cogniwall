from __future__ import annotations

from agentguard.rules.base import Rule, resolve_field
from agentguard.verdict import Verdict

VALID_PRESETS = frozenset({"angry", "sarcastic", "apologetic", "threatening", "dismissive"})


class ToneSentimentRule(Rule):
    tier = 2
    rule_name = "tone_sentiment"

    def __init__(
        self,
        field: str,
        block: list[str] | None = None,
        custom: list[str] | None = None,
        provider: str = "anthropic",
        model: str = "claude-haiku-4-5-20251001",
        api_key: str | None = None,
        api_key_env: str | None = None,
    ):
        self.field = field
        self.block = block or []
        self.custom = custom or []
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.api_key_env = api_key_env

    async def evaluate(self, payload: dict) -> Verdict:
        value = resolve_field(payload, self.field)
        if value is None or not isinstance(value, str):
            return Verdict.approved()

        try:
            matched_tone = await self._call_llm(value)
            if matched_tone.upper() == "NONE":
                return Verdict.approved()
            return Verdict.blocked(
                rule=self.rule_name,
                reason=f"Tone detected: {matched_tone}",
                details={"tone": matched_tone, "field": self.field},
            )
        except Exception as exc:
            return Verdict.error(rule=self.rule_name, error=exc)

    async def _call_llm(self, text: str) -> str:
        """Call the LLM to classify text tone. Returns tone name or 'NONE'."""
        import os

        api_key = self.api_key
        if not api_key and self.api_key_env:
            api_key = os.environ.get(self.api_key_env)

        if not api_key:
            raise ValueError(
                f"No API key provided. Set api_key or api_key_env for {self.provider}."
            )

        all_tones = self.block + self.custom
        tone_list = ", ".join(f'"{t}"' for t in all_tones)

        prompt = (
            f"Analyze the tone of the following text. "
            f"Does it match any of these tones: {tone_list}?\n\n"
            f"Respond with ONLY the matched tone name (exactly as listed) "
            f"or 'NONE' if no match.\n\n"
            f"Text:\n{text}"
        )

        if self.provider == "anthropic":
            return await self._call_anthropic(api_key, prompt)
        elif self.provider == "openai":
            return await self._call_openai(api_key, prompt)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    async def _call_anthropic(self, api_key: str, prompt: str) -> str:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=self.model,
            max_tokens=50,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()

    async def _call_openai(self, api_key: str, prompt: str) -> str:
        import openai

        client = openai.AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model=self.model,
            max_tokens=50,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content.strip()

    @classmethod
    def from_config(cls, config: dict) -> ToneSentimentRule:
        return cls(
            field=config["field"],
            block=config.get("block", []),
            custom=config.get("custom", []),
            provider=config.get("provider", "anthropic"),
            model=config.get("model", "claude-haiku-4-5-20251001"),
            api_key=config.get("api_key"),
            api_key_env=config.get("api_key_env"),
        )
