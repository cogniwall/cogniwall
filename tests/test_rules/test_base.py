import pytest
from cogniwall.rules.base import Rule, resolve_field


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
    from cogniwall.verdict import Verdict

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


class TestResolveField:
    def test_top_level_field(self):
        assert resolve_field({"amount": 100}, "amount") == 100

    def test_nested_field(self):
        assert resolve_field({"data": {"refund": {"amount": 50}}}, "data.refund.amount") == 50

    def test_missing_field(self):
        assert resolve_field({"other": 1}, "amount") is None

    def test_missing_nested_field(self):
        assert resolve_field({"data": {}}, "data.refund.amount") is None

    def test_non_dict_intermediate(self):
        assert resolve_field({"data": "string"}, "data.inner") is None

    def test_none_value(self):
        assert resolve_field({"amount": None}, "amount") is None
