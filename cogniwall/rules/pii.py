from __future__ import annotations

from collections.abc import Callable

from cogniwall.patterns import find_credit_cards, find_emails, find_phones, find_ssns
from cogniwall.rules.base import Rule, extract_strings, normalize_for_matching, try_base64_decode
from cogniwall.verdict import Verdict

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
        if block is not None and not isinstance(block, list):
            raise TypeError(
                f"PiiDetectionRule 'block' must be a list, got {type(block).__name__}"
            )
        if custom_terms is not None and not isinstance(custom_terms, list):
            raise TypeError(
                f"PiiDetectionRule 'custom_terms' must be a list, got {type(custom_terms).__name__}"
            )
        self.block = block or []
        self.custom_terms = custom_terms or []

    async def evaluate(self, payload: dict) -> Verdict:
        texts = extract_strings(payload, include_keys=True)
        if not texts:
            return Verdict.approved()

        # Also extract values only (no keys) for cross-field concatenation
        values_only = extract_strings(payload, include_keys=False)

        combined = "\n".join(texts)
        concatenated = " ".join(texts)

        # Try base64 decoding on each extracted string
        decoded_texts = []
        for text in texts:
            b64 = try_base64_decode(text)
            if b64:
                decoded_texts.append(b64)
        if decoded_texts:
            combined = combined + "\n" + "\n".join(decoded_texts)
            concatenated = concatenated + " " + " ".join(decoded_texts)

        # Cross-field concatenation: try pairwise gluing of digit-heavy fragment
        # values to catch PII split across fields without false positives
        def _is_pii_fragment(s: str) -> bool:
            """True if the string looks like a PII fragment (mostly digits/separators)."""
            if not s or len(s) > 20:
                return False
            digit_sep_count = sum(1 for c in s if c.isdigit() or c in "-. ,")
            return digit_sep_count / len(s) >= 0.6

        fragments = [v for v in values_only if _is_pii_fragment(v)]
        pairwise_texts = []
        for i in range(len(fragments)):
            for j in range(len(fragments)):
                if i != j:
                    pairwise_texts.append(fragments[i] + fragments[j])

        for pii_type in self.block:
            scanner = _SCANNERS.get(pii_type)
            if scanner:
                matches = scanner(combined)
                if not matches:
                    matches = scanner(concatenated)
                if not matches:
                    for pair_text in pairwise_texts:
                        matches = scanner(pair_text)
                        if matches:
                            break
                if matches:
                    return Verdict.blocked(
                        rule=self.rule_name,
                        reason=f"PII detected: {pii_type}",
                        details={"matched": matches, "type": pii_type},
                    )

        if self.custom_terms:
            normalized_combined = normalize_for_matching(combined).casefold()
            for term in self.custom_terms:
                normalized_term = normalize_for_matching(term).casefold()
                if normalized_term in normalized_combined:
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
