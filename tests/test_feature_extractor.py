from ml.extractor import (
    calculate_urgency_score,
    count_suspicious_keywords,
    extract_email_features,
    extract_sender_domain,
    extract_urls,
    to_metadata_dataframe,
)


def test_extract_sender_domain() -> None:
    assert extract_sender_domain("Support <support@paypal-security.com>") == "paypal-security.com"
    assert extract_sender_domain("john@company.org") == "company.org"
    assert extract_sender_domain("") == "unknown"


def test_extract_urls() -> None:
    text = "Visit https://secure-login.bank.com/auth and http://insecure.site.org now."
    urls = extract_urls(text)
    assert len(urls) == 2
    assert "https://secure-login.bank.com/auth" in urls
    assert "http://insecure.site.org" in urls


def test_calculate_urgency_score() -> None:
    text = "This is urgent! Immediate action required within 24 hours."
    score = calculate_urgency_score(text)
    assert score >= 4


def test_count_suspicious_keywords() -> None:
    text = "Please verify your account credentials or your password will be suspended."
    count = count_suspicious_keywords(text)
    assert count >= 3


def test_to_metadata_dataframe() -> None:
    extracted = extract_email_features(
        subject="Urgent Security Alert",
        body="Please check attached invoice.pdf and click https://portal.example.com immediately.",
        sender="Security Team <security@corp.example.com>",
    )
    df = to_metadata_dataframe(extracted)
    assert len(df) == 1
    assert df["num_links"].iloc[0] == 1
    assert df["urgency_score"].iloc[0] >= 3
    assert df["contains_attachment_bin"].iloc[0] == 1
    assert df["attachment_type"].iloc[0] == "pdf"
