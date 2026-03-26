from cogniwall.verdict import Verdict


def test_approved_verdict():
    v = Verdict.approved(elapsed_ms=1.5)
    assert v.status == "approved"
    assert v.blocked is False
    assert v.rule is None
    assert v.reason is None
    assert v.details is None
    assert v.error is None
    assert v.elapsed_ms == 1.5


def test_blocked_verdict():
    v = Verdict.blocked(
        rule="pii_detection",
        reason="SSN detected",
        details={"matched": ["123-45-6789"]},
        elapsed_ms=0.3,
    )
    assert v.status == "blocked"
    assert v.blocked is True
    assert v.rule == "pii_detection"
    assert v.reason == "SSN detected"
    assert v.details == {"matched": ["123-45-6789"]}
    assert v.error is None


def test_error_verdict():
    exc = RuntimeError("API timeout")
    v = Verdict.error(
        rule="prompt_injection",
        error=exc,
        elapsed_ms=5000.0,
    )
    assert v.status == "error"
    assert v.blocked is False
    assert v.error is exc
    assert v.rule == "prompt_injection"
