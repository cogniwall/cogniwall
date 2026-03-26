"""CogniWall — a programmable firewall for autonomous AI agents."""

from cogniwall.guard import CogniWall
from cogniwall.verdict import Verdict
from cogniwall.rules.pii import PiiDetectionRule
from cogniwall.rules.financial import FinancialLimitRule
from cogniwall.rules.prompt_injection import PromptInjectionRule
from cogniwall.rules.tone_sentiment import ToneSentimentRule
from cogniwall.rules.rate_limit import RateLimitRule

__all__ = [
    "CogniWall",
    "Verdict",
    "PiiDetectionRule",
    "FinancialLimitRule",
    "PromptInjectionRule",
    "ToneSentimentRule",
    "RateLimitRule",
]
