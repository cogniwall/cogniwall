"""AgentGuard — a programmable firewall for autonomous AI agents."""

from agentguard.guard import AgentGuard
from agentguard.verdict import Verdict
from agentguard.rules.pii import PiiDetectionRule
from agentguard.rules.financial import FinancialLimitRule
from agentguard.rules.prompt_injection import PromptInjectionRule
from agentguard.rules.tone_sentiment import ToneSentimentRule
from agentguard.rules.rate_limit import RateLimitRule

__all__ = [
    "AgentGuard",
    "Verdict",
    "PiiDetectionRule",
    "FinancialLimitRule",
    "PromptInjectionRule",
    "ToneSentimentRule",
    "RateLimitRule",
]
