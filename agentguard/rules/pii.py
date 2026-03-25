from __future__ import annotations

from collections.abc import Callable

from agentguard.patterns import find_credit_cards, find_emails, find_phones, find_ssns
from agentguard.rules.base import Rule, extract_strings
from agentguard.verdict import Verdict

_SCANNERS: dict[str, Callable[[str], list[str]]] = {
    "ssn": find_ssns,
    "credit_card": find_credit_cards,
    "email": find_emails,
    "phone": find_phones,
}


class PiiDetectionRule(Rule):
    tier = 1
    rule_name = "pii_detection"

    def __init__(
        self,
        block: list[str] | None = None,
        custom_terms: list[str] | None = None,
    ):
        self.block = block or []
        self.custom_terms = custom_terms or []

    async def evaluate(self, payload: dict) -> Verdict:
        texts = extract_strings(payload)
        if not texts:
            return Verdict.approved()

        combined = "\n".join(texts)

        # Check each enabled PII type
        for pii_type in self.block:
            scanner = _SCANNERS.get(pii_type)
            if scanner:
                matches = scanner(combined)
                if matches:
                    return Verdict.blocked(
                        rule=self.rule_name,
                        reason=f"PII detected: {pii_type}",
                        details={"matched": matches, "type": pii_type},
                    )

        # Check custom terms
        for term in self.custom_terms:
            if term.lower() in combined.lower():
                return Verdict.blocked(
                    rule=self.rule_name,
                    reason=f"Custom term detected: {term}",
                    details={"matched": [term], "type": "custom_term"},
                )

        return Verdict.approved()

    @classmethod
    def from_config(cls, config: dict) -> PiiDetectionRule:
        return cls(
            block=config.get("block", []),
            custom_terms=config.get("custom_terms", []),
        )
