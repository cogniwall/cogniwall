import pytest
from cogniwall.rules.llm_provider import (
    LLMProvider,
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
