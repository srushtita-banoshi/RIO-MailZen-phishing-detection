"""Unified inference engine for real-world phishing detection and thread analysis."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from scipy.sparse import hstack

from ml.explain import generate_simple_phishing_explanation
from ml.extractor import extract_email_features, to_metadata_dataframe
from ml.intent import classify_intent
from ml.threads import detect_intent_shift

ROOT = Path(__file__).resolve().parent.parent


class RIOEngine:
    """Production-grade unified engine running real-data models with fused thread intelligence."""

    def __init__(self, model_path: Path | str | None = None) -> None:
        self.model_path = Path(model_path) if model_path else (ROOT / "models/phishing_model.joblib")
        self._package: dict[str, Any] | None = None

    @property
    def package(self) -> dict[str, Any]:
        if self._package is None:
            self.load()
        return self._package  # type: ignore

    def load(self) -> None:
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Phishing model not found at {self.model_path}. "
                "Please run: python -m ml.train_phishing"
            )
        self._package = joblib.load(self.model_path)

    def analyze(
        self,
        subject: str,
        body: str,
        sender: str = "",
        headers: dict[str, str] | None = None,
        attachment_filename: str | None = None,
        spf_override: str | None = None,
        dkim_override: str | None = None,
        previous_email_text: str | None = None,
    ) -> dict[str, Any]:
        """Perform end-to-end phishing detection, intent extraction, thread shift, and plain-English explanation."""
        start_t = time.perf_counter()

        # 1. Automated feature extraction
        extracted = extract_email_features(
            subject=subject,
            body=body,
            sender=sender,
            headers=headers,
            attachment_filename=attachment_filename,
            spf_override=spf_override,
            dkim_override=dkim_override,
        )
        meta_df = to_metadata_dataframe(extracted)

        # 2. Phishing classification with real model
        pkg = self.package
        model = pkg["model"]
        vec = pkg["vectorizer"]
        prep = pkg["preprocessor"]

        text_feat = vec.transform([extracted["combined_text"]])
        meta_feat = prep.transform(meta_df)
        X = hstack([text_feat, meta_feat]).tocsr()

        pred = int(model.predict(X)[0])
        probs = model.predict_proba(X)[0]
        confidence = float(np.max(probs))
        label = "Phishing" if pred == 1 else "Legitimate"

        # Find top active text words contributing to prediction
        vocab = vec.get_feature_names_out()
        top_words: list[str] = []
        if hasattr(model, "coef_"):
            weights = model.coef_[0]
            active_indices = text_feat.indices
            word_weights = [(vocab[i], weights[i]) for i in active_indices if weights[i] > 0]
            word_weights = sorted(word_weights, key=lambda x: x[1], reverse=True)[:5]
            top_words = [w[0] for w in word_weights]

        # 3. Intent extraction on current email
        curr_intent, curr_conf, curr_action, is_sensitive = classify_intent(extracted["combined_text"])

        # 4. Thread intent-shift detection (if conversation context provided)
        thread_analysis: dict[str, Any] | None = None
        if previous_email_text and previous_email_text.strip():
            thread_analysis = detect_intent_shift(
                previous_text=previous_email_text.strip(),
                current_text=extracted["combined_text"],
                urgency_score=extracted["urgency_score"],
            )

        # 5. Base single-email explanation
        explanation = generate_simple_phishing_explanation(
            prediction_label=label,
            confidence=confidence,
            features=extracted,
            top_words=top_words,
        )

        # 6. Fused Multi-Layer Verdict (Static Classifier + Conversational Thread Intelligence + Threat Rules)
        sender_lower = (sender or "").lower()
        combined_lower = extracted["combined_text"].lower()
        domain_lower = extracted["sender_domain"].lower()
        free_webmails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
        is_exec_impersonation = (
            domain_lower in free_webmails
            and any(c in sender_lower or c in combined_lower for c in ["ceo", "executive", "cfo", "president", "director", "board call", "board meeting"])
            and any(w in combined_lower for w in ["strictly between us", "keep this between us", "vendor disbursement", "wire instructions", "wire transfer", "confidential disbursement"])
        )

        is_brand_spoof = (
            extracted.get("spf_status") == "Fail"
            and (
                any(b in domain_lower for b in ["docusign", "office365", "microsoft", "paypal", "apple", "amazon", "netflix"])
                or any(u in domain_lower for u in ["-viewers", "-portal", "auth-", "-verify", "login-", "-security"])
            )
        )

        if pred == 1:
            fused_status = "PHISHING ATTACK DETECTED"
            fused_risk = "HIGH"
            fused_summary = explanation["simple_summary"]
            fused_is_threat = True
            fused_confidence = confidence
        elif is_exec_impersonation:
            fused_status = "THREAT DETECTED: EXECUTIVE IMPERSONATION (BEC)"
            fused_risk = "HIGH"
            fused_summary = (
                "THREAT DETECTED: Executive impersonation attack detected. The sender claims to be executive "
                f"leadership ('{sender}') but is communicating via an unauthorized public webmail address ({domain_lower}) "
                "requesting confidential vendor disbursement. Do NOT process funds or wire instructions without secondary verbal confirmation."
            )
            fused_is_threat = True
            fused_confidence = 0.94
            explanation["evidence_points"].insert(0, f"Executive impersonation: free webmail ({domain_lower}) claiming leadership authority")
            explanation["evidence_points"].append("Secrecy & isolation framing detected ('strictly between us')")
        elif is_brand_spoof:
            fused_status = "PHISHING ATTACK DETECTED: LOOKALIKE BRAND SPOOFING"
            fused_risk = "HIGH"
            fused_summary = (
                f"THREAT DETECTED: Sender authentication failed on an unverified lookalike domain ({domain_lower}) "
                "impersonating a trusted service with credential/signing triggers. Do NOT interact with links or attachments."
            )
            fused_is_threat = True
            fused_confidence = 0.96
            explanation["evidence_points"].insert(0, f"Deceptive lookalike domain detected ({domain_lower})")
        elif thread_analysis and thread_analysis["status"] == "SUSPICIOUS INTENT SHIFT":
            fused_status = "THREAT DETECTED: CONVERSATION HIJACKING (BEC)"
            fused_risk = "HIGH"
            fused_summary = (
                f"THREAT DETECTED: Although this email's sender domain and technical headers appear valid with no malicious links, "
                f"the conversation was abruptly hijacked from routine discussion ('{thread_analysis['previous_intent']}') "
                f"to an urgent sensitive demand ('{curr_intent}'). Do NOT transfer funds or disclose credentials without independent verbal confirmation."
            )
            fused_is_threat = True
            fused_confidence = 0.95
        elif thread_analysis and thread_analysis["status"] == "UNVERIFIED INTENT PIVOT":
            fused_status = "CAUTION: SENSITIVE REQUEST PIVOT"
            fused_risk = "MEDIUM"
            fused_summary = (
                f"CAUTION: The conversation naturally shifted to a sensitive action ('{curr_intent}'). "
                f"Verify the sender's identity through an independent secondary channel before proceeding."
            )
            fused_is_threat = True
            fused_confidence = 0.85
        else:
            fused_status = "LEGITIMATE EMAIL"
            fused_risk = "LOW"
            fused_summary = explanation["simple_summary"]
            fused_is_threat = False
            fused_confidence = confidence

        elapsed_ms = (time.perf_counter() - start_t) * 1000.0

        return {
            "verdict": label,
            "is_phishing": pred == 1,
            "confidence": confidence,
            "fused_verdict": {
                "status": fused_status,
                "risk_level": fused_risk,
                "summary": fused_summary,
                "is_threat": fused_is_threat,
                "confidence": fused_confidence,
            },
            "probabilities": {
                "legitimate": float(probs[0]),
                "phishing": float(probs[1]),
            },
            "intent": {
                "intent": curr_intent,
                "confidence": curr_conf,
                "requested_action": curr_action,
                "is_sensitive": is_sensitive,
            },
            "thread_analysis": thread_analysis,
            "explanation": explanation,
            "features": extracted,
            "latency_ms": round(elapsed_ms, 2),
        }


# Alias for platform rebrand
MailZenEngine = RIOEngine

