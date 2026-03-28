from __future__ import annotations

import os
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Base class for LLM providers.

    Subclasses must set:
        provider_name: str -- identifier used in config (e.g. "anthropic")
    """

    provider_name: str

    @abstractmethod
    async def call(self, prompt: str, model: str, max_tokens: int = 10) -> str:
        """Send a prompt and return the raw text response."""
        ...

    @classmethod
    @abstractmethod
    def from_config(cls, config: dict) -> LLMProvider:
        """Construct from rule-level YAML config dict."""
        ...


def _resolve_api_key(config: dict) -> str | None:
    """Resolve API key from config: direct value or environment variable."""
    api_key = config.get("api_key")
    if not api_key:
        env_var = config.get("api_key_env")
        if env_var:
            api_key = os.environ.get(env_var)
    return api_key


class AnthropicProvider(LLMProvider):
    provider_name = "anthropic"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def call(self, prompt: str, model: str, max_tokens: int = 10) -> str:
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "Anthropic provider requires the anthropic package. "
                "Install it with: pip install cogniwall[anthropic]"
            )
        client = anthropic.AsyncAnthropic(api_key=self.api_key)
        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()

    @classmethod
    def from_config(cls, config: dict) -> AnthropicProvider:
        api_key = _resolve_api_key(config)
        if not api_key:
            raise ValueError(
                "Anthropic provider requires an API key. "
                "Set 'api_key' or 'api_key_env' in your config."
            )
        return cls(api_key=api_key)


class OpenAIProvider(LLMProvider):
    provider_name = "openai"

    def __init__(self, api_key: str | None, base_url: str | None = None):
        self.api_key = api_key
        self.base_url = base_url

    async def call(self, prompt: str, model: str, max_tokens: int = 10) -> str:
        try:
            import openai
        except ImportError:
            raise ImportError(
                "OpenAI provider requires the openai package. "
                "Install it with: pip install cogniwall[openai]"
            )
        kwargs: dict = {"api_key": self.api_key or "unused"}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        client = openai.AsyncOpenAI(**kwargs)
        response = await client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content.strip()

    @classmethod
    def from_config(cls, config: dict) -> OpenAIProvider:
        api_key = _resolve_api_key(config)
        base_url = config.get("base_url")
        if not api_key and not base_url:
            raise ValueError(
                "OpenAI provider requires an API key. "
                "Set 'api_key' or 'api_key_env' in your config. "
                "For local endpoints, set 'base_url' instead."
            )
        return cls(api_key=api_key, base_url=base_url)


class GeminiProvider(LLMProvider):
    provider_name = "gemini"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def call(self, prompt: str, model: str, max_tokens: int = 10) -> str:
        try:
            from google import genai
        except ImportError:
            raise ImportError(
                "Gemini provider requires the google-genai package. "
                "Install it with: pip install cogniwall[gemini]"
            )
        client = genai.Client(api_key=self.api_key)
        response = await client.aio.models.generate_content(
            model=model,
            contents=prompt,
            config=genai.types.GenerateContentConfig(max_output_tokens=max_tokens),
        )
        return response.text.strip()

    @classmethod
    def from_config(cls, config: dict) -> GeminiProvider:
        api_key = _resolve_api_key(config)
        if not api_key:
            raise ValueError(
                "Gemini provider requires an API key. "
                "Set 'api_key' or 'api_key_env' in your config."
            )
        return cls(api_key=api_key)


_PROVIDER_REGISTRY: dict[str, type[LLMProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
}


def register_provider(name: str, cls: type[LLMProvider]) -> None:
    """Register a custom LLM provider for use in YAML config."""
    _PROVIDER_REGISTRY[name] = cls


def get_provider(config: dict) -> LLMProvider:
    """Look up provider by name and instantiate from config."""
    name = config.get("provider", "anthropic")
    if name not in _PROVIDER_REGISTRY:
        raise ValueError(
            f"Unknown provider: {name!r}. "
            f"Available: {sorted(_PROVIDER_REGISTRY)}"
        )
    return _PROVIDER_REGISTRY[name].from_config(config)
