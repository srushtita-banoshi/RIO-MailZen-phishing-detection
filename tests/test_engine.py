from ml.engine import RIOEngine


def test_rio_engine_analyze_phishing_and_thread() -> None:
    engine = RIOEngine()
    result = engine.analyze(
        subject="Critical Security Alert: Immediate verification needed",
        body="Please sign in to http://login-portal.example.com to verify your employee credentials immediately within 24 hours.",
        sender="Security Desk <security@login-portal.example.com>",
        spf_override="Fail",
        previous_email_text="Hi team, thanks for sending over the quarterly marketing review.",
    )

    assert result["verdict"] == "Phishing"
    assert result["is_phishing"] is True
    assert 0.8 <= result["confidence"] <= 1.0
    assert result["latency_ms"] > 0
    assert result["thread_analysis"] is not None
    assert result["thread_analysis"]["status"] == "SUSPICIOUS INTENT SHIFT"
    assert "PHISHING" in result["explanation"]["simple_summary"]


def test_rio_engine_analyze_legitimate_email() -> None:
    engine = RIOEngine()
    result = engine.analyze(
        subject="Agenda and materials for tomorrow's project sync",
        body="Hi team, I have finalized the agenda for our project sync meeting tomorrow at 10:00 AM UTC. Please review the plan.",
        sender="Sarah <sarah@company.com>",
        spf_override="Pass",
        dkim_override="Pass",
    )

    assert result["verdict"] == "Legitimate"
    assert result["is_phishing"] is False
    assert result["thread_analysis"] is None
    assert "LEGITIMATE" in result["explanation"]["simple_summary"]
