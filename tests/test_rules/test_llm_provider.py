import pytest
from cogniwall.rules.llm_provider import (
    LLMProvider,
    AnthropicProvider,
    OpenAIProvider,
    GeminiProvider,
    _PROVIDER_REGISTRY,
    register_provider,
    get_provider,
)


class TestLLMProviderABC:
    def test_cannot_instantiate_abc(self):
        """LLMProvider is abstract and cannot be instantiated directly."""
        with pytest.raises(TypeError):
            LLMProvider()

    def test_subclass_must_implement_call(self):
        """Subclass that only implements from_config cannot be instantiated."""
        class Incomplete(LLMProvider):
            provider_name = "incomplete"

            @classmethod
            def from_config(cls, config):
                return cls()

        with pytest.raises(TypeError):
            Incomplete()

    def test_subclass_must_implement_from_config(self):
        """Subclass that only implements call cannot be instantiated."""
        class Incomplete(LLMProvider):
            provider_name = "incomplete"

            async def call(self, prompt, model, max_tokens=10):
                return ""

        with pytest.raises(TypeError):
            Incomplete()


class TestProviderRegistry:
    def test_builtin_providers_registered(self):
        assert "anthropic" in _PROVIDER_REGISTRY
        assert "openai" in _PROVIDER_REGISTRY
        assert "gemini" in _PROVIDER_REGISTRY

    def test_register_custom_provider(self):
        class FakeProvider(LLMProvider):
            provider_name = "fake"

            async def call(self, prompt, model, max_tokens=10):
                return "fake response"

            @classmethod
            def from_config(cls, config):
                return cls()

        register_provider("fake", FakeProvider)
        assert "fake" in _PROVIDER_REGISTRY
        # Clean up
        del _PROVIDER_REGISTRY["fake"]

    def test_get_provider_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown provider.*'nonexistent'"):
            get_provider({"provider": "nonexistent"})

    def test_get_provider_default_is_anthropic(self):
        """When no provider key, defaults to anthropic."""
        assert _PROVIDER_REGISTRY.get("anthropic") is not None


class TestAnthropicProvider:
    def test_from_config_with_api_key(self):
        provider = AnthropicProvider.from_config({"api_key": "sk-test"})
        assert isinstance(provider, AnthropicProvider)
        assert provider.api_key == "sk-test"

    def test_from_config_with_api_key_env(self, monkeypatch):
        monkeypatch.setenv("TEST_ANTHROPIC_KEY", "sk-from-env")
        provider = AnthropicProvider.from_config({"api_key_env": "TEST_ANTHROPIC_KEY"})
        assert provider.api_key == "sk-from-env"

    def test_from_config_missing_key_raises(self):
        with pytest.raises(ValueError, match="API key"):
            AnthropicProvider.from_config({})

    def test_from_config_env_var_not_set_raises(self):
        with pytest.raises(ValueError, match="API key"):
            AnthropicProvider.from_config({"api_key_env": "NONEXISTENT_VAR_12345"})


class TestOpenAIProvider:
    def test_from_config_with_api_key(self):
        provider = OpenAIProvider.from_config({"api_key": "sk-test"})
        assert isinstance(provider, OpenAIProvider)
        assert provider.api_key == "sk-test"
        assert provider.base_url is None

    def test_from_config_with_base_url(self):
        provider = OpenAIProvider.from_config({
            "base_url": "http://127.0.0.1:11434/v1",
        })
        assert isinstance(provider, OpenAIProvider)
        assert provider.base_url == "http://127.0.0.1:11434/v1"
        assert provider.api_key is None

    def test_from_config_with_both(self):
        provider = OpenAIProvider.from_config({
            "api_key": "sk-test",
            "base_url": "http://localhost:18789/v1",
        })
        assert provider.api_key == "sk-test"
        assert provider.base_url == "http://localhost:18789/v1"

    def test_from_config_no_key_no_base_url_raises(self):
        with pytest.raises(ValueError, match="API key"):
            OpenAIProvider.from_config({})


class TestGeminiProvider:
    def test_from_config_with_api_key(self):
        provider = GeminiProvider.from_config({"api_key": "gem-test"})
        assert isinstance(provider, GeminiProvider)
        assert provider.api_key == "gem-test"

    def test_from_config_with_api_key_env(self, monkeypatch):
        monkeypatch.setenv("TEST_GEMINI_KEY", "gem-from-env")
        provider = GeminiProvider.from_config({"api_key_env": "TEST_GEMINI_KEY"})
        assert provider.api_key == "gem-from-env"

    def test_from_config_missing_key_raises(self):
        with pytest.raises(ValueError, match="API key"):
            GeminiProvider.from_config({})


class TestGetProvider:
    def test_get_anthropic_provider(self):
        provider = get_provider({"provider": "anthropic", "api_key": "sk-test"})
        assert isinstance(provider, AnthropicProvider)

    def test_get_openai_provider(self):
        provider = get_provider({"provider": "openai", "api_key": "sk-test"})
        assert isinstance(provider, OpenAIProvider)

    def test_get_gemini_provider(self):
        provider = get_provider({"provider": "gemini", "api_key": "gem-test"})
        assert isinstance(provider, GeminiProvider)

    def test_get_openai_with_base_url(self):
        provider = get_provider({
            "provider": "openai",
            "base_url": "http://127.0.0.1:11434/v1",
        })
        assert isinstance(provider, OpenAIProvider)
        assert provider.base_url == "http://127.0.0.1:11434/v1"

    def test_default_provider_is_anthropic(self):
        provider = get_provider({"api_key": "sk-test"})
        assert isinstance(provider, AnthropicProvider)
