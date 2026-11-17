"""Multi-feature extractor for raw emails matching the real phishing dataset schema."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import pandas as pd

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>'\"`]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")

SUSPICIOUS_KEYWORDS = [
    "verify", "verification", "password", "credential", "credentials", "account",
    "suspended", "suspension", "urgent", "urgently", "immediate", "immediately",
    "security alert", "unauthorized", "confirm", "login", "sign in", "expire",
    "billing", "invoice", "bank", "transfer", "wire", "wire transfer", "action required",
    "compromised", "validate", "locked", "reset"
]

COMMON_EXTENSIONS = {
    ".pdf": "pdf",
    ".docx": "docx",
    ".doc": "docx",
    ".xlsx": "xlsx",
    ".xls": "xlsx",
    ".exe": "exe",
    ".zip": "zip",
}

BRAND_TARGETS = [
    "paypal", "microsoft", "office365", "google", "amazon", "apple", "netflix",
    "chase", "bank", "wells fargo", "support desk", "service desk"
]


def extract_sender_domain(sender_str: str) -> str:
    """Extract domain from sender string (e.g. 'Security <alert@amazon.com>' -> 'amazon.com')."""
    if not sender_str:
        return "unknown"
    match = EMAIL_PATTERN.search(sender_str)
    if match:
        return match.group(1).lower()
    if "@" in sender_str:
        return sender_str.split("@")[-1].strip().lower()
    return sender_str.strip().lower()


def extract_urls(text: str) -> list[str]:
    """Extract all URLs from text, unpacking open-redirect destinations."""
    if not text:
        return []
    urls = [match.group(0).rstrip(".,;:)") for match in URL_PATTERN.finditer(text)]
    unpacked: list[str] = []
    for u in urls:
        unpacked.append(u)
        # Unmask open-redirect targets (e.g. google.com/url?q=http://...)
        if "url?q=" in u or "url?url=" in u:
            match = re.search(r"(?:q|url)=(https?://[^\s&]+)", u)
            if match:
                unpacked.append(match.group(1))
    return unpacked


def calculate_urgency_score(text: str) -> int:
    """Calculate an urgency score on a 1-10 scale based on urgency triggers."""
    if not text:
        return 1
    urgency_cues = [
        r"\burgent\b", r"\burgently\b", r"\bimmediate\b", r"\bimmediately\b",
        r"\basap\b", r"\baction required\b", r"\bwithin 24 hours\b",
        r"\bwithin 48 hours\b", r"\bexpire\b", r"\bfailure to respond\b",
        r"\baccount suspended\b", r"\bdeadline\b", r"\bcritical\b",
        r"\bbefore 3:00 pm\b", r"\bbefore 2:00 pm\b", r"\bas soon as you see\b"
    ]
    count = 0
    lower = text.lower()
    for cue in urgency_cues:
        count += len(re.findall(cue, lower))
    return min(10, max(1, 1 + count * 2))


def count_suspicious_keywords(text: str) -> int:
    """Count how many known phishing/security keywords appear in the text."""
    if not text:
        return 0
    lower = text.lower()
    count = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            count += 1
    return count


def detect_attachment_info(text: str, filename: str | None = None) -> tuple[int, str]:
    """Detect if an attachment exists and its file type."""
    if filename:
        ext = "." + filename.split(".")[-1].lower() if "." in filename else ""
        return 1, COMMON_EXTENSIONS.get(ext, "other")
    for ext, att_type in COMMON_EXTENSIONS.items():
        if re.search(rf"\w+{re.escape(ext)}\b", text, re.IGNORECASE):
            return 1, att_type
    return 0, "none"


def auto_evaluate_domain_trust(sender_domain: str, combined_text: str, sender_str: str = "") -> str:
    """Intelligently infer spoofing risk when user does not know technical SPF/DKIM headers."""
    domain_lower = sender_domain.lower()
    text_lower = combined_text.lower()
    sender_lower = (sender_str or "").lower()

    # 1. Brand impersonation in domain name (e.g. login-office365.com, docusign-viewers.net)
    for brand in ["office365", "microsoft", "paypal", "amazon", "apple", "netflix", "docusign", "dropbox", "google"]:
        if brand in domain_lower and not (domain_lower.endswith(f".{brand}.com") or domain_lower == f"{brand}.com"):
            return "Fail"

    # 2. Deceptive domain patterns (hyphenated alert/security/portal domains)
    if any(k in domain_lower for k in ["login-", "portal-", "-verify", "-security", "update-", "auth-", "-viewers", "-sso"]):
        return "Fail"

    # 3. Executive / Internal impersonation over free public webmail (CEO Fraud / Zero-link BEC)
    free_webmails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    exec_cues = ["ceo", "executive", "cfo", "president", "director", "board call", "board meeting", "hr compensation"]
    if domain_lower in free_webmails and any(c in sender_lower or c in text_lower for c in exec_cues):
        if any(w in text_lower for w in ["strictly between us", "keep this between us", "vendor disbursement", "wire instructions", "wire transfer", "confidential disbursement"]):
            return "Fail"

    # 4. Text claims to be from a major brand, but domain is unrelated/generic
    for brand in ["microsoft", "paypal", "apple", "amazon", "docusign"]:
        if brand in text_lower and brand not in domain_lower:
            if any(u in text_lower for u in ["suspended", "within 24 hours", "verify your credentials", "document ready for signature", "sign electronically"]):
                return "Fail"

    return "Pass"



def extract_email_features(
    subject: str,
    body: str,
    sender: str = "",
    headers: dict[str, str] | None = None,
    attachment_filename: str | None = None,
    spf_override: str | None = None,
    dkim_override: str | None = None,
    dmarc_override: str | None = None,
) -> dict[str, Any]:
    """Extract full feature set required by RIO models matching real dataset schema."""
    combined_text = f"{subject} {body}".strip()
    sender_domain = extract_sender_domain(sender)
    urls = extract_urls(combined_text)
    num_links = len(urls)
    has_links = 1 if num_links > 0 else 0

    urgency_score = calculate_urgency_score(combined_text)
    suspicious_count = count_suspicious_keywords(combined_text)
    has_attachment, attachment_type = detect_attachment_info(combined_text, attachment_filename)

    # Intelligent Auto-Detection of SPF & DKIM if user leaves them as None or Auto-Detect
    if spf_override in (None, "Auto-Detect (Default)", ""):
        spf = auto_evaluate_domain_trust(sender_domain, combined_text, sender)
    else:
        spf = spf_override

    if dkim_override in (None, "Auto-Detect (Default)", ""):
        dkim = spf  # Correlate with domain verification
    else:
        dkim = dkim_override

    dmarc = dmarc_override or "Pass"

    # Override with actual technical headers if provided
    if headers:
        auth_header = (
            headers.get("Authentication-Results", "") + " " + headers.get("Received-SPF", "")
        ).lower()
        if "spf=fail" in auth_header or "fail" in auth_header:
            spf = "Fail"
        elif "spf=pass" in auth_header or "pass" in auth_header:
            spf = "Pass"

        if "dkim=fail" in auth_header:
            dkim = "Fail"
        elif "dkim=pass" in auth_header:
            dkim = "Pass"

    return {
        "subject": subject,
        "body": body,
        "combined_text": combined_text,
        "sender_domain": sender_domain,
        "urls": urls,
        "num_links": float(num_links),
        "contains_link_bin": has_links,
        "contains_attachment_bin": has_attachment,
        "attachment_type": attachment_type,
        "urgency_score": float(urgency_score),
        "suspicious_keyword_count": float(suspicious_count),
        "spf_status": spf,
        "dkim_status": dkim,
        "dmarc_status": dmarc,
    }


def to_metadata_dataframe(extracted: dict[str, Any]) -> pd.DataFrame:
    """Convert extracted feature dict into DataFrame for ColumnTransformer."""
    return pd.DataFrame([{
        "num_links": extracted["num_links"],
        "urgency_score": extracted["urgency_score"],
        "suspicious_keyword_count": extracted["suspicious_keyword_count"],
        "contains_link_bin": extracted["contains_link_bin"],
        "contains_attachment_bin": extracted["contains_attachment_bin"],
        "spf_status": extracted["spf_status"],
        "dkim_status": extracted["dkim_status"],
        "dmarc_status": extracted["dmarc_status"],
        "attachment_type": extracted["attachment_type"],
    }])
