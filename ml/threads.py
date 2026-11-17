"""Multi-turn conversation thread processing and intent-shift detection for RIO."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

from ml.intent import SENSITIVE_INTENTS, classify_intent, extract_requested_action

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class ConversationMessage:
    turn_index: int
    thread_id: int | str
    timestamp: str
    sender: str
    recipient: str
    subject: str
    body: str
    cleaned_body: str


@dataclass
class ConversationThread:
    thread_id: int | str
    subject: str
    messages: list[ConversationMessage] = field(default_factory=list)

    @property
    def turn_count(self) -> int:
        return len(self.messages)


def clean_body_text(raw_text: str) -> str:
    """Clean quoted-printable artifacts and reply block quotes from raw email body."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        return ""
    text = raw_text.replace("=20", " ").replace("=09", " ").replace("=\n", "")
    text = re.sub(r"=([0-9A-Fa-f]{2})", " ", text)
    # Strip forwarded and original message reply sections
    text = re.sub(
        r"-+\s*(?:Original Message|Forwarded by|Forwarded Message)\s*-+[\s\S]*?(?:Subject:|Date:|To:|From:)[^\n]*\n",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"^\s*>.*$", "", text, flags=re.MULTILINE)
    return re.sub(r"\s+", " ", text).strip()


def calculate_text_similarity(text1: str, text2: str) -> float:
    """Calculate TF-IDF cosine similarity between two texts."""
    if not text1.strip() or not text2.strip():
        return 0.0
    vec = TfidfVectorizer(ngram_range=(1, 2), lowercase=True)
    try:
        tfidf = vec.fit_transform([text1, text2])
        sim = (tfidf[0] @ tfidf[1].T).toarray()[0, 0]
        return float(np.clip(sim, 0.0, 1.0))
    except Exception:
        return 0.0


def load_sample_threads(
    csv_path: Path | str | None = None,
    max_threads: int = 30,
    min_turns: int = 2,
    max_rows: int = 10000,
) -> dict[str, ConversationThread]:
    """Safely load real multi-turn conversation threads from email_thread_details.csv."""
    path = Path(csv_path) if csv_path else (ROOT / "data/raw/email_thread_details.csv")
    if not path.exists():
        return {}

    chunks = pd.read_csv(
        path,
        nrows=max_rows,
        usecols=["thread_id", "subject", "timestamp", "from", "to", "body"],
        dtype={"thread_id": str, "subject": str, "timestamp": str, "from": str, "to": str, "body": str},
    )

    chunks["timestamp"] = pd.to_datetime(chunks["timestamp"], errors="coerce")
    chunks = chunks.sort_values(by=["thread_id", "timestamp"]).reset_index(drop=True)

    threads: dict[str, ConversationThread] = {}

    for thread_id, group in chunks.groupby("thread_id", sort=False):
        if len(group) < min_turns:
            continue
        first_subject = str(group["subject"].dropna().iloc[0]) if not group["subject"].dropna().empty else "No Subject"
        conv = ConversationThread(thread_id=str(thread_id), subject=first_subject)

        for turn_idx, (_, row) in enumerate(group.iterrows()):
            raw_b = str(row["body"]) if pd.notna(row["body"]) else ""
            cleaned_b = clean_body_text(raw_b) or raw_b[:200]
            msg = ConversationMessage(
                turn_index=turn_idx,
                thread_id=str(thread_id),
                timestamp=str(row["timestamp"]) if pd.notna(row["timestamp"]) else "",
                sender=str(row["from"]) if pd.notna(row["from"]) else "Unknown",
                recipient=str(row["to"]) if pd.notna(row["to"]) else "Unknown",
                subject=str(row["subject"]) if pd.notna(row["subject"]) else "",
                body=raw_b,
                cleaned_body=cleaned_b,
            )
            conv.messages.append(msg)

        threads[str(thread_id)] = conv
        if len(threads) >= max_threads:
            break

    return threads


def detect_intent_shift(
    previous_text: str,
    current_text: str,
    urgency_score: float = 1.0,
) -> dict[str, Any]:
    """Detect if an incoming reply represents a suspicious conversation hijack or legitimate change."""
    prev_intent, prev_conf, prev_action, prev_sensitive = classify_intent(previous_text)
    curr_intent, curr_conf, curr_action, curr_sensitive = classify_intent(current_text)

    similarity = calculate_text_similarity(previous_text, current_text)
    intent_changed = prev_intent != curr_intent

    # High urgency cues in current message
    has_urgency = urgency_score >= 4.0 or bool(
        re.search(r"\b(urgent|urgently|immediately|within 24 hours|action required)\b", current_text, re.IGNORECASE)
    )

    # Core Security Logic:
    # If the previous conversation was benign, but current reply suddenly demands sensitive action + urgency:
    is_suspicious = (not prev_sensitive) and curr_sensitive and has_urgency

    if is_suspicious:
        status = "SUSPICIOUS INTENT SHIFT"
        risk_level = "HIGH"
        simple_explanation = (
            f"Alert: Earlier messages in this thread established a benign topic ('{prev_intent}'), "
            f"but this message abruptly demanded sensitive action ('{curr_intent}') under urgency pressure. "
            f"This strongly indicates conversational hijacking or Business Email Compromise (BEC)."
        )
    elif intent_changed and curr_sensitive:
        status = "UNVERIFIED INTENT PIVOT"
        risk_level = "MEDIUM"
        simple_explanation = (
            f"Notice: The conversation topic shifted from '{prev_intent}' to a sensitive request ('{curr_intent}'). "
            f"Verify the sender's identity through an independent channel before proceeding."
        )
    elif intent_changed:
        status = "LEGITIMATE INTENT CHANGE"
        risk_level = "LOW"
        simple_explanation = (
            f"The conversation naturally changed topics from '{prev_intent}' to '{curr_intent}' "
            f"without anomalous urgency or sensitive credential/financial demands."
        )
    else:
        status = "NORMAL CONTINUATION"
        risk_level = "LOW"
        simple_explanation = f"The email naturally continues the established topic ('{curr_intent}') with high continuity."

    return {
        "status": status,
        "risk_level": risk_level,
        "previous_intent": prev_intent,
        "current_intent": curr_intent,
        "previous_action": prev_action or "None",
        "current_action": curr_action or "None",
        "is_sensitive_escalation": curr_sensitive and not prev_sensitive,
        "continuity_similarity": round(similarity, 3),
        "has_urgency_pressure": has_urgency,
        "simple_explanation": simple_explanation,
    }
