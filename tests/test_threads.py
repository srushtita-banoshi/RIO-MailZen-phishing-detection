from pathlib import Path

import pandas as pd

from ml.threads import (
    clean_body_text,
    detect_intent_shift,
    load_sample_threads,
)


def test_clean_body_text() -> None:
    raw = "Here is the plan =20 for tomorrow.\n -----Original Message-----\n From: boss@corp.com\n Sent: yesterday\n Old notes"
    cleaned = clean_body_text(raw)
    assert "=20" not in cleaned
    assert "Original Message" not in cleaned
    assert "Here is the plan for tomorrow" in cleaned


def test_load_sample_threads(tmp_path: Path) -> None:
    sample_csv = tmp_path / "email_thread_details.csv"
    data = [
        {"thread_id": "101", "subject": "Review Request", "timestamp": "2026-01-01 10:00:00", "from": "alice@corp.com", "to": "bob@corp.com", "body": "Please review the attached notes."},
        {"thread_id": "101", "subject": "Re: Review Request", "timestamp": "2026-01-01 11:00:00", "from": "bob@corp.com", "to": "alice@corp.com", "body": "Looks good to me."},
        {"thread_id": "102", "subject": "One-off", "timestamp": "2026-01-01 12:00:00", "from": "charlie@corp.com", "to": "david@corp.com", "body": "Single message."},
    ]
    pd.DataFrame(data).to_csv(sample_csv, index=False)

    threads = load_sample_threads(sample_csv, min_turns=2)
    assert len(threads) == 1
    assert "101" in threads
    assert threads["101"].turn_count == 2


def test_detect_intent_shift_suspicious() -> None:
    prev = "Can we schedule a planning meeting next week to go over the roadmap?"
    curr = "Also, urgently submit your employee credentials before the review can continue."
    res = detect_intent_shift(prev, curr, urgency_score=7.0)

    assert res["status"] == "SUSPICIOUS INTENT SHIFT"
    assert res["risk_level"] == "HIGH"
    assert res["is_sensitive_escalation"] is True
    assert "Alert" in res["simple_explanation"]


def test_detect_intent_shift_safe_continuation() -> None:
    prev = "Can we schedule a planning meeting next week?"
    curr = "Please find a time that works for everyone for the planning session."
    res = detect_intent_shift(prev, curr, urgency_score=1.0)

    assert res["status"] == "NORMAL CONTINUATION"
    assert res["risk_level"] == "LOW"
