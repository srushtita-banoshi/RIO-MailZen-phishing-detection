"""Simple, human-readable explanations for RIO phishing and thread analysis."""

from __future__ import annotations

from typing import Any

import numpy as np


def generate_simple_phishing_explanation(
    prediction_label: str,
    confidence: float,
    features: dict[str, Any],
    top_words: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generate a simple, 1-2 sentence plain-English explanation for why an email
    was classified as Phishing or Legitimate, plus bullet-point evidence.
    """
    is_phishing = prediction_label.lower() == "phishing"

    reasons: list[str] = []

    # Authentication indicators
    if features.get("spf_status") == "Fail" or features.get("dkim_status") == "Fail":
        reasons.append("Email sender authentication failed (SPF/DKIM fail — indicates possible sender spoofing)")

    # Urgency indicators
    urgency = features.get("urgency_score", 1)
    if urgency >= 4:
        reasons.append(f"High urgency and deadline pressure detected (urgency score: {int(urgency)}/10)")

    # Suspicious keywords
    keywords_count = features.get("suspicious_keyword_count", 0)
    if keywords_count >= 2:
        reasons.append(f"Multiple high-risk keywords detected (e.g. login, verify, suspended, credentials)")

    # Links
    num_links = features.get("num_links", 0)
    if num_links > 0:
        reasons.append(f"{int(num_links)} external link(s) prompting user action")

    # Attachment
    att_type = features.get("attachment_type", "none")
    if att_type in ("exe", "zip"):
        reasons.append(f"High-risk executable or archive attachment ({att_type})")

    # Summary sentence in plain English
    if is_phishing:
        if reasons:
            main_triggers = ", ".join(reasons[:2])
            simple_sentence = (
                f"Flagged as PHISHING ({confidence:.1%} confidence) primarily because of: {main_triggers}."
            )
        else:
            simple_sentence = (
                f"Flagged as PHISHING ({confidence:.1%} confidence) because the email structure and language "
                f"closely match known phishing email patterns."
            )
    else:
        simple_sentence = (
            f"Classified as LEGITIMATE ({confidence:.1%} confidence). The email exhibits normal organizational "
            f"communication with valid sender authentication, no deceptive links, and no coercive deadline demands."
        )

    return {
        "verdict": prediction_label.upper(),
        "confidence": confidence,
        "simple_summary": simple_sentence,
        "evidence_points": reasons,
        "suspicious_terms": top_words or [],
    }
