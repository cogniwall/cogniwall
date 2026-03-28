"""CogniWall — a programmable firewall for autonomous AI agents."""

__version__ = "0.1.1"

from cogniwall.guard import CogniWall
from cogniwall.verdict import Verdict
from cogniwall.rules.pii import PiiDetectionRule
from cogniwall.rules.financial import FinancialLimitRule
from cogniwall.rules.prompt_injection import PromptInjectionRule
from cogniwall.rules.tone_sentiment import ToneSentimentRule
from cogniwall.rules.rate_limit import RateLimitRule
from cogniwall.audit import AuditClient

__all__ = [
    "__version__",
    "CogniWall",
    "Verdict",
    "AuditClient",
    "PiiDetectionRule",
    "FinancialLimitRule",
    "PromptInjectionRule",
    "ToneSentimentRule",
    "RateLimitRule",
]
