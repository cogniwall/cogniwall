from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class Verdict:
    """Immutable result returned by every guardrail rule evaluation."""

    status: Literal["approved", "blocked", "error"]
    blocked: bool = False
    rule: str | None = None
    reason: str | None = None
    details: dict[str, Any] | None = None
    error: Exception | None = None
    elapsed_ms: float = 0.0


# Attach factory classmethods after class definition to avoid name-shadowing
# in Python 3.14+, where classmethods defined inside the class body take
# precedence over same-named dataclass fields during instance attribute lookup.


def _approved(cls: type[Verdict], elapsed_ms: float = 0.0) -> Verdict:
    return cls(status="approved", blocked=False, elapsed_ms=elapsed_ms)


def _blocked(
    cls: type[Verdict],
    rule: str,
    reason: str,
    details: dict[str, Any] | None = None,
    elapsed_ms: float = 0.0,
) -> Verdict:
    return cls(
        status="blocked",
        blocked=True,
        rule=rule,
        reason=reason,
        details=details,
        elapsed_ms=elapsed_ms,
    )


def _error_factory(
    cls: type[Verdict],
    rule: str,
    error: Exception,
    elapsed_ms: float = 0.0,
) -> Verdict:
    return cls(
        status="error",
        blocked=False,
        rule=rule,
        error=error,
        elapsed_ms=elapsed_ms,
    )


Verdict.approved = classmethod(_approved)  # type: ignore[method-assign]
Verdict.blocked = classmethod(_blocked)  # type: ignore[method-assign]
Verdict.error = classmethod(_error_factory)  # type: ignore[method-assign]
