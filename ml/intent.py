"""Intent classification and sensitive action extraction for RIO."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parent.parent

ACTION_PATTERN = re.compile(
    r"\b(?:review|check|schedule|share|submit|transfer|verify|confirm|download|grant|approve|read|send|forward|pay|wire)\b[^.!?\n]*",
    re.IGNORECASE,
)

SENSITIVE_INTENTS = {
    "credential_submission",
    "financial_transfer",
    "account_verification",
    "payment_confirmation",
    "access_permission",
}

INTENT_KEYWORDS: dict[str, list[str]] = {
    "credential_submission": ["credentials", "password", "sign in", "login details", "submit your credentials", "employee portal", "auth"],
    "financial_transfer": ["transfer funds", "wire transfer", "payment account", "bank transfer", "transfer the approved", "wire amount"],
    "account_verification": ["verify account", "verification", "confirm your details", "account activity", "validate profile"],
    "payment_confirmation": ["confirm payment", "invoice payment", "payment receipt", "payment confirmed", "invoice status"],
    "access_permission": ["grant access", "folder access", "permission to access", "approve access", "restricted folder"],
    "meeting_scheduling": ["schedule a meeting", "planning session", "calendar invite", "sync meeting", "zoom call", "agenda tomorrow"],
    "document_review": ["review the project", "review attached", "feedback on the draft", "read the document", "comments on proposal"],
    "file_download": ["download file", "download attachment", "shared workspace file", "download the report"],
    "information_sharing": ["status update", "sharing information", "latest update", "here is the report", "notes from discussion"],
    "general_inquiry": ["general announcement", "please let me know", "quick question", "touch base", "notice"],
}


def extract_requested_action(text: str) -> str:
    """Extract the primary imperative / requested action phrase from text."""
    if not text:
        return ""
    match = ACTION_PATTERN.search(text)
    return match.group(0).strip() if match else ""


def build_default_intent_model() -> dict[str, Any]:
    """Train a robust semantic n-gram intent classifier using domain keywords."""
    corpus = []
    labels = []
    for intent, phrases in INTENT_KEYWORDS.items():
        for phrase in phrases:
            corpus.append(phrase)
            labels.append(intent)
            corpus.append(f"Please {phrase} as soon as possible.")
            labels.append(intent)
            corpus.append(f"Could you {phrase}?")
            labels.append(intent)
            corpus.append(f"Regarding our discussion, {phrase}.")
            labels.append(intent)

    vec = TfidfVectorizer(ngram_range=(1, 2), lowercase=True)
    X = vec.fit_transform(corpus)
    clf = LogisticRegression(max_iter=500, random_state=42)
    clf.fit(X, labels)

    package = {"model": clf, "vectorizer": vec, "classes": list(clf.classes_)}
    out_path = ROOT / "models/intent_model.joblib"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(package, out_path)
    return package


def get_intent_model() -> dict[str, Any]:
    path = ROOT / "models/intent_model.joblib"
    if path.exists():
        return joblib.load(path)
    return build_default_intent_model()


def classify_intent(text: str, package: dict[str, Any] | None = None) -> tuple[str, float, str, bool]:
    """Classify the intent of an email and determine if it represents a sensitive action."""
    if not text:
        return "general_inquiry", 0.5, "", False

    pkg = package or get_intent_model()
    vec = pkg["vectorizer"]
    clf = pkg["model"]

    X = vec.transform([text])
    probs = clf.predict_proba(X)[0]
    idx = int(np.argmax(probs))
    intent = str(clf.classes_[idx])
    confidence = float(probs[idx])
    action = extract_requested_action(text)
    is_sensitive = intent in SENSITIVE_INTENTS

    return intent, confidence, action, is_sensitive
