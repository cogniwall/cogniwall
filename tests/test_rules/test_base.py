import pytest
from agentguard.rules.base import Rule


def test_rule_is_abstract():
    """Cannot instantiate Rule directly."""
    with pytest.raises(TypeError):
        Rule()


def test_rule_subclass_must_implement_evaluate():
    """Subclass that doesn't implement evaluate raises TypeError."""

    class IncompleteRule(Rule):
        tier = 1
        rule_name = "incomplete"

        @classmethod
        def from_config(cls, config: dict) -> "IncompleteRule":
            return cls()

    with pytest.raises(TypeError):
        IncompleteRule()


def test_rule_subclass_with_evaluate():
    """Subclass that implements all abstract methods can be instantiated."""
    from agentguard.verdict import Verdict

    class DummyRule(Rule):
        tier = 1
        rule_name = "dummy"

        async def evaluate(self, payload: dict) -> Verdict:
            return Verdict.approved()

        @classmethod
        def from_config(cls, config: dict) -> "DummyRule":
            return cls()

    rule = DummyRule()
    assert rule.tier == 1
    assert rule.rule_name == "dummy"
