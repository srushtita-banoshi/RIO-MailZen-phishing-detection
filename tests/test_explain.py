from ml.explain import generate_simple_phishing_explanation


def test_generate_simple_phishing_explanation_phish() -> None:
    features = {
        "spf_status": "Fail",
        "dkim_status": "Fail",
        "urgency_score": 7,
        "suspicious_keyword_count": 3,
        "num_links": 2,
        "attachment_type": "none",
    }
    exp = generate_simple_phishing_explanation(
        prediction_label="Phishing",
        confidence=0.98,
        features=features,
        top_words=["verify", "suspended", "credentials"],
    )

    assert exp["verdict"] == "PHISHING"
    assert exp["confidence"] == 0.98
    assert "PHISHING" in exp["simple_summary"]
    assert len(exp["evidence_points"]) >= 2
    assert "verify" in exp["suspicious_terms"]


def test_generate_simple_phishing_explanation_legit() -> None:
    features = {
        "spf_status": "Pass",
        "dkim_status": "Pass",
        "urgency_score": 1,
        "suspicious_keyword_count": 0,
        "num_links": 0,
        "attachment_type": "none",
    }
    exp = generate_simple_phishing_explanation(
        prediction_label="Legitimate",
        confidence=0.99,
        features=features,
    )

    assert exp["verdict"] == "LEGITIMATE"
    assert "LEGITIMATE" in exp["simple_summary"]
