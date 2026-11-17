"""MailZen Threat Intelligence Platform — Executive Cybersecurity Console.

Enterprise UI with refined dark slate navy canvas, eye-catching MailZen brand badge,
compact scenario buttons, larger typography, and zero extraneous decorations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import streamlit as st

from ml.engine import MailZenEngine, RIOEngine
from ml.threads import load_sample_threads

ROOT = Path(__file__).resolve().parent

SAMPLE_PRESETS: dict[str, dict[str, Any]] = {
    "phishing": {
        "id": "phishing",
        "label": "Scenario 1: Phishing Attack",
        "subject": "Critical Security Alert: Immediate verification needed for your account",
        "sender": "IT Support Desk <Security-update@login-portal-office365.com>",
        "body": (
            "Your account access will be suspended within 24 hours unless you verify your identity "
            "immediately. Please sign in to http://login-portal-office365.com/auth/verify to confirm your "
            "employee credentials.\n"
            "Failure to respond will require administrative account lock.\n\n"
            "Regards,\n"
            "Corporate Security Desk"
        ),
        "has_thread": False,
        "previous_email": "",
    },
    "legitimate": {
        "id": "legitimate",
        "label": "Scenario 2: Legitimate Message",
        "subject": "Agenda and materials for tomorrow's project sync",
        "sender": "Sarah Jenkins <s.jenkins@company.com>",
        "body": (
            "Hi team,\n\n"
            "I have finalized the agenda for our project sync meeting tomorrow at 10:00 AM UTC. "
            "Please review the attached plan and share your feedback by Thursday if you have any suggestions.\n\n"
            "Looking forward to our discussion.\n\n"
            "Best regards,\n"
            "Sarah"
        ),
        "has_thread": False,
        "previous_email": "",
    },
    "conversation_hijack": {
        "id": "conversation_hijack",
        "label": "Scenario 3: Conversation Hijacking",
        "subject": "Re: Quarterly Financial Review & Planning",
        "sender": "Executive Office <finance-update@corp-secure-payments.com>",
        "body": (
            "Also John, regarding our previous discussion below,\n\n"
            "We urgently need you to transfer the approved funds of $48,500 to the new supplier account "
            "before 3 PM today to prevent service interruption. Please confirm the wire transfer immediately.\n\n"
            "Thank you,\n"
            "Finance Operations"
        ),
        "has_thread": True,
        "previous_email": (
            "Hi John, thanks for sending over the quarterly marketing review notes. "
            "I will look through the numbers this afternoon and schedule a planning session for next week."
        ),
    },
}

CONSOLE_DARK_CSS = """
<style>
/* Remove Streamlit default header chrome, deploy button, footer */
[data-testid="stDeployButton"],
.stDeployButton,
[data-testid="stToolbar"],
header[data-testid="stHeader"] .stDeployButton,
#MainMenu,
footer {
    display: none !important;
    visibility: hidden !important;
}

header[data-testid="stHeader"] {
    display: none !important;
    height: 0 !important;
    min-height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
}

/* Base Canvas: Softer, slightly lighter dark slate navy (not pitch black) */
.stApp {
    background-color: #0E1424;
    color: #F8FAFC;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background-image: radial-gradient(rgba(45, 60, 85, 0.4) 1px, transparent 1px);
    background-size: 28px 28px;
}

/* Eliminate top empty space */
.main .block-container {
    max-width: 1260px;
    padding-top: 0.35rem !important;
    padding-bottom: 2.5rem !important;
    padding-left: 1.5rem !important;
    padding-right: 1.5rem !important;
}

/* Top Navigation Bar */
.top-navbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background-color: #141C30;
    border: 1px solid #24334D;
    border-radius: 12px;
    padding: 12px 22px;
    margin-bottom: 20px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
}

.brand-group {
    display: flex;
    align-items: center;
    gap: 14px;
}

/* Eye-Catching, Larger MailZen Brand Badge */
.brand-badge {
    background: linear-gradient(135deg, #6366F1 0%, #4F46E5 100%);
    color: #FFFFFF;
    font-weight: 800;
    font-size: 1.10rem;
    letter-spacing: 0.04em;
    padding: 6px 20px;
    border-radius: 24px;
    box-shadow: 0 0 18px rgba(99, 102, 241, 0.65), 0 2px 6px rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.3);
    display: inline-flex;
    align-items: center;
    justify-content: center;
}

.brand-name {
    font-size: 1.25rem;
    font-weight: 700;
    color: #FFFFFF;
    letter-spacing: -0.01em;
}

.brand-subtitle-nav {
    font-size: 0.90rem;
    color: #8191A6;
    border-left: 1px solid #24334D;
    padding-left: 14px;
    margin-left: 4px;
}

.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background-color: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.40);
    color: #10B981;
    font-size: 0.88rem;
    font-weight: 600;
    padding: 6px 16px;
    border-radius: 20px;
    box-shadow: 0 0 14px rgba(16, 185, 129, 0.2);
}

.status-dot {
    width: 9px;
    height: 9px;
    background-color: #10B981;
    border-radius: 50%;
    box-shadow: 0 0 10px #10B981;
}

/* Main Dashboard Header */
.page-header {
    margin-bottom: 20px;
}

.page-title {
    font-size: 2.10rem;
    font-weight: 800;
    color: #FFFFFF;
    margin: 0 0 6px 0;
    letter-spacing: -0.03em;
}

.page-description {
    font-size: 1.00rem;
    color: #A3B3C8;
    margin: 0;
    line-height: 1.5;
}

/* 4 Overview Metrics Cards */
.metrics-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 22px;
}

@media (max-width: 900px) {
    .metrics-row {
        grid-template-columns: repeat(2, 1fr);
    }
}

.metric-card-1 {
    background: linear-gradient(135deg, rgba(37, 99, 235, 0.28) 0%, #131D33 100%);
    border: 1px solid #2563EB;
    border-radius: 10px;
    padding: 16px 20px;
}

.metric-card-2 {
    background: linear-gradient(135deg, rgba(16, 185, 129, 0.24) 0%, #131D33 100%);
    border: 1px solid #059669;
    border-radius: 10px;
    padding: 16px 20px;
}

.metric-card-3 {
    background: linear-gradient(135deg, rgba(6, 182, 212, 0.24) 0%, #131D33 100%);
    border: 1px solid #0891B2;
    border-radius: 10px;
    padding: 16px 20px;
}

.metric-card-4 {
    background: #141C30;
    border: 1px solid #24334D;
    border-radius: 10px;
    padding: 16px 20px;
}

.metric-card-label {
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #9EAFCE;
    margin-bottom: 4px;
}

.metric-card-value {
    font-size: 1.55rem;
    font-weight: 800;
    color: #38BDF8;
    margin: 0;
    letter-spacing: -0.02em;
}

.metric-card-value-green {
    font-size: 1.55rem;
    font-weight: 800;
    color: #10B981;
    margin: 0;
    letter-spacing: -0.02em;
}

.metric-card-value-cyan {
    font-size: 1.55rem;
    font-weight: 800;
    color: #22D3EE;
    margin: 0;
    letter-spacing: -0.02em;
}

.metric-card-value-white {
    font-size: 1.55rem;
    font-weight: 800;
    color: #F8FAFC;
    margin: 0;
    letter-spacing: -0.02em;
}

.metric-card-sub {
    font-size: 0.84rem;
    color: #9EAFCE;
    margin-top: 3px;
}

/* Demonstration Scenarios Selector */
.preset-bar-title {
    font-size: 0.80rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #9EAFCE;
    margin-bottom: 10px;
}

/* Compact Scenario Buttons (No wide empty space behind) */
div[data-testid="stHorizontalBlock"] button[kind="secondary"] {
    background-color: #141C2E !important;
    border: 1px solid #24334D !important;
    color: #CBD5E1 !important;
    font-size: 0.94rem !important;
    font-weight: 600 !important;
    border-radius: 20px !important;
    padding: 8px 18px !important;
    white-space: nowrap !important;
    transition: all 0.2s ease !important;
}

div[data-testid="stHorizontalBlock"] button[kind="secondary"]:hover {
    background-color: #1B263E !important;
    border-color: #6366F1 !important;
    color: #FFFFFF !important;
}

/* Workspace Headers */
.workspace-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 14px;
}

.workspace-title {
    font-size: 1.25rem;
    font-weight: 700;
    color: #FFFFFF;
    margin: 0;
}

.workspace-pill {
    background-color: #7C3AED;
    color: #FFFFFF;
    font-size: 0.80rem;
    font-weight: 700;
    padding: 4px 14px;
    border-radius: 14px;
    letter-spacing: 0.02em;
    box-shadow: 0 0 10px rgba(124, 58, 237, 0.4);
}

/* Form Inputs Styling */
.stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"] {
    background-color: #11182A !important;
    border: 1px solid #24334D !important;
    border-radius: 6px !important;
    color: #F8FAFC !important;
    font-size: 0.96rem !important;
}

.stTextInput input:focus, .stTextArea textarea:focus {
    border-color: #6366F1 !important;
    box-shadow: 0 0 0 1px #6366F1, 0 0 12px rgba(99, 102, 241, 0.35) !important;
}

.stTextInput label, .stTextArea label, .stSelectbox label {
    color: #E2E8F0 !important;
    font-size: 0.92rem !important;
    font-weight: 600 !important;
    margin-bottom: 5px !important;
}

/* Primary Action Button */
button[kind="primary"] {
    background: linear-gradient(90deg, #6366F1 0%, #4F46E5 50%, #3B82F6 100%) !important;
    border: none !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
    font-size: 1.05rem !important;
    border-radius: 8px !important;
    padding: 13px 28px !important;
    box-shadow: 0 4px 22px rgba(79, 70, 229, 0.55) !important;
    transition: all 0.2s ease !important;
    letter-spacing: 0.02em !important;
}

button[kind="primary"]:hover {
    background: linear-gradient(90deg, #4F46E5 0%, #4338CA 50%, #2563EB 100%) !important;
    box-shadow: 0 6px 26px rgba(79, 70, 229, 0.7) !important;
}

/* Empty State Card (Star Removed) */
.empty-state-card {
    background-color: #131D33;
    border: 1px solid #223049;
    border-radius: 10px;
    padding: 60px 28px;
    text-align: center;
    position: relative;
    overflow: hidden;
    min-height: 380px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
}

.radar-graphic {
    margin-bottom: 20px;
}

.empty-state-headline {
    font-size: 1.30rem;
    font-weight: 700;
    color: #FFFFFF;
    margin: 0 0 10px 0;
    letter-spacing: -0.01em;
}

.empty-state-text {
    font-size: 0.96rem;
    color: #A3B3C8;
    max-width: 440px;
    margin: 0 auto;
    line-height: 1.55;
}

/* Verdict Banners */
.verdict-banner-threat {
    background: linear-gradient(180deg, rgba(239, 68, 68, 0.18) 0%, rgba(185, 28, 28, 0.07) 100%);
    border: 1px solid rgba(239, 68, 68, 0.45);
    border-left: 5px solid #EF4444;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 20px;
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.15);
}

.verdict-banner-caution {
    background: linear-gradient(180deg, rgba(245, 158, 11, 0.18) 0%, rgba(180, 83, 9, 0.07) 100%);
    border: 1px solid rgba(245, 158, 11, 0.45);
    border-left: 5px solid #F59E0B;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 20px;
    box-shadow: 0 0 20px rgba(245, 158, 11, 0.15);
}

.verdict-banner-safe {
    background: linear-gradient(180deg, rgba(16, 185, 129, 0.18) 0%, rgba(4, 120, 87, 0.07) 100%);
    border: 1px solid rgba(16, 185, 129, 0.45);
    border-left: 5px solid #10B981;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 20px;
    box-shadow: 0 0 20px rgba(16, 185, 129, 0.15);
}

.verdict-banner-title {
    font-size: 1.35rem;
    font-weight: 800;
    margin: 0 0 8px 0;
    letter-spacing: -0.01em;
}

.verdict-banner-threat .verdict-banner-title { color: #FCA5A5; }
.verdict-banner-caution .verdict-banner-title { color: #FCD34D; }
.verdict-banner-safe .verdict-banner-title { color: #6EE7B7; }

.verdict-banner-body {
    color: #F1F5F9;
    font-size: 0.98rem;
    line-height: 1.6;
    margin: 0;
}

/* Trajectory Timeline Comparison */
.trajectory-box {
    background-color: #141C30;
    border: 1px solid #24334D;
    border-radius: 8px;
    padding: 18px;
    margin-bottom: 18px;
}

.timeline-step {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid #24334D;
}

.timeline-step:last-child {
    border-bottom: none;
    padding-bottom: 0;
}

.timeline-marker {
    background-color: rgba(99, 102, 241, 0.18);
    color: #C7D2FE;
    font-size: 0.76rem;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 4px;
    text-transform: uppercase;
    border: 1px solid rgba(99, 102, 241, 0.35);
}

.timeline-marker-alert {
    background-color: rgba(239, 68, 68, 0.20);
    color: #FCA5A5;
    font-size: 0.76rem;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 4px;
    text-transform: uppercase;
    border: 1px solid rgba(239, 68, 68, 0.40);
}

.timeline-content-title {
    font-size: 0.90rem;
    font-weight: 600;
    color: #FFFFFF;
    margin-bottom: 3px;
}

.timeline-content-body {
    font-size: 0.88rem;
    color: #A3B3C8;
}

/* Telemetry Grid */
.telemetry-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-bottom: 18px;
}

.telemetry-cell {
    background-color: #141C30;
    border: 1px solid #24334D;
    border-radius: 8px;
    padding: 14px 16px;
}

.telemetry-label {
    font-size: 0.76rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #9EAFCE;
}

.telemetry-value {
    font-size: 1.22rem;
    font-weight: 700;
    color: #FFFFFF;
    margin-top: 3px;
}

/* Tag Chips */
.chip {
    display: inline-block;
    background-color: #1B263E;
    color: #E2E8F0;
    font-size: 0.82rem;
    font-weight: 600;
    padding: 5px 12px;
    border-radius: 4px;
    margin-right: 6px;
    margin-bottom: 6px;
    border: 1px solid #2A3C5E;
}

.indicator-bullet {
    background-color: #141C30;
    border: 1px solid #24334D;
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 0.90rem;
    color: #E2E8F0;
    margin-bottom: 8px;
}
</style>
"""


@st.cache_resource
def get_engine() -> RIOEngine:
    return RIOEngine()


@st.cache_data(show_spinner=False)
def get_cached_threads() -> dict[Any, Any]:
    try:
        return load_sample_threads(max_threads=25, min_turns=2)
    except Exception:
        return {}


def apply_preset(name: str) -> None:
    preset = SAMPLE_PRESETS[name]
    st.session_state["in_subject"] = preset["subject"]
    st.session_state["in_sender"] = preset["sender"]
    st.session_state["in_body"] = preset["body"]
    st.session_state["in_has_thread"] = preset["has_thread"]
    st.session_state["in_prev_text"] = preset["previous_email"]
    st.session_state["active_preset"] = name


def main() -> None:
    st.set_page_config(
        page_title="Threat Analysis — MailZen Platform",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    st.markdown(CONSOLE_DARK_CSS, unsafe_allow_html=True)

    try:
        engine = get_engine()
    except Exception as e:
        st.error(f"Engine initialization error: {e}")
        st.stop()

    # Session State Initialization
    if "session_analyzed_count" not in st.session_state:
        st.session_state["session_analyzed_count"] = 0
    if "last_result" not in st.session_state:
        st.session_state["last_result"] = None
    if "active_preset" not in st.session_state:
        st.session_state["active_preset"] = "phishing"
    if "in_subject" not in st.session_state:
        apply_preset("phishing")

    # 1. Compact Top Navigation Bar (Zero extra top gap)
    st.markdown(
        """
        <div class="top-navbar">
            <div class="brand-group">
                <span class="brand-badge">MailZen</span>
                <span class="brand-name">Threat Intelligence</span>
                <span class="brand-subtitle-nav">Security Operations Console</span>
            </div>
            <div style="display: flex; align-items: center; gap: 14px;">
                <div class="status-badge">
                    <span class="status-dot"></span>
                    <span>System Operational</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Main Dashboard Header
    st.markdown(
        """
        <div class="page-header">
            <h1 class="page-title">Threat Analysis</h1>
            <p class="page-description">
                Inspect incoming emails, detect phishing attempts and identify suspicious changes in email conversations.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. 4 Overview Metrics Cards with Sparkline
    st.markdown(
        f"""
        <div class="metrics-row">
            <div class="metric-card-1">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div class="metric-card-label">TRAINING CORPUS</div>
                        <div class="metric-card-value">50,000</div>
                    </div>
                    <svg width="54" height="26" viewBox="0 0 54 26" fill="none" style="filter: drop-shadow(0 0 6px rgba(56, 189, 248, 0.4));">
                        <path d="M 2 20 Q 14 6, 24 16 T 40 8 T 52 4" stroke="#38BDF8" stroke-width="2.5" fill="none" stroke-linecap="round"/>
                    </svg>
                </div>
                <div class="metric-card-sub">Verified real-world emails</div>
            </div>
            <div class="metric-card-2">
                <div class="metric-card-label">PHISHING MODEL</div>
                <div class="metric-card-value-green">Active</div>
                <div class="metric-card-sub">L2 regularized pipeline</div>
            </div>
            <div class="metric-card-3">
                <div class="metric-card-label">CONVERSATION ANALYSIS</div>
                <div class="metric-card-value-cyan">Enabled</div>
                <div class="metric-card-sub">Multi-turn BEC trajectory</div>
            </div>
            <div class="metric-card-4">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div class="metric-card-label">SESSION INSPECTIONS</div>
                        <div class="metric-card-value-white">{st.session_state['session_analyzed_count']}</div>
                    </div>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#9EAFCE" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="16" y1="13" x2="8" y2="13"></line>
                        <line x1="16" y1="17" x2="8" y2="17"></line>
                    </svg>
                </div>
                <div class="metric-card-sub">Emails inspected this session</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 4. Compact Demonstration Presets (Horizontal size fitted, no wide background stretch)
    st.markdown('<div class="preset-bar-title">DEMONSTRATION SCENARIOS</div>', unsafe_allow_html=True)
    c_p1, c_p2, c_p3, _spacer = st.columns([1.05, 0.95, 1.15, 1.35])
    curr_active = st.session_state.get("active_preset", "phishing")

    with c_p1:
        label_p1 = "Scenario 1: Phishing Attack" + (" (Selected) •" if curr_active == "phishing" else "")
        if st.button(label_p1, use_container_width=True, key="btn_pre_1"):
            apply_preset("phishing")
            st.rerun()

    with c_p2:
        label_p2 = "Scenario 2: Legitimate Message" + (" (Selected) •" if curr_active == "legitimate" else "")
        if st.button(label_p2, use_container_width=True, key="btn_pre_2"):
            apply_preset("legitimate")
            st.rerun()

    with c_p3:
        label_p3 = "Scenario 3: Conversation Hijacking" + (" (Selected) •" if curr_active == "conversation_hijack" else "")
        if st.button(label_p3, use_container_width=True, key="btn_pre_3"):
            apply_preset("conversation_hijack")
            st.rerun()

    st.write("")

    # 5. Two-Column Workspace
    col_input, col_results = st.columns([1.05, 1.15], gap="medium")

    # ------------------ LEFT COLUMN: Incoming Email ------------------
    with col_input:
        st.markdown(
            """
            <div class="workspace-header">
                <span class="workspace-title">Incoming Email Inspection</span>
                <span class="workspace-pill">Workspace</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        input_subject = st.text_input("Email Subject", key="in_subject")
        input_sender = st.text_input("Sender Address", key="in_sender")

        input_body = st.text_area(
            "Message Body",
            height=180,
            key="in_body",
            placeholder="Paste raw email body text...",
        )

        st.write("")
        has_thread = st.checkbox(
            "Include prior conversation thread context (evaluate trajectory / hijacking)",
            key="in_has_thread",
        )

        previous_email_text = ""
        if has_thread:
            thread_mode = st.radio(
                "Thread Source",
                ["Direct Context Input", "Benchmark Thread Corpus"],
                horizontal=True,
                label_visibility="collapsed",
            )

            if thread_mode == "Direct Context Input":
                previous_email_text = st.text_area(
                    "Preceding Message in Thread (Turn t-1)",
                    height=100,
                    key="in_prev_text",
                    placeholder="Paste the earlier message in this email thread...",
                )
            else:
                threads = get_cached_threads()
                if threads:
                    tid = st.selectbox(
                        "Benchmark Thread Selection",
                        list(threads.keys()),
                        format_func=lambda t: f"Thread #{t}: {threads[t].subject} ({threads[t].turn_count} turns)",
                    )
                    selected_thread = threads[tid]
                    st.caption(f"Historical messages in Thread #{tid}:")
                    prior_turns = [
                        f"Turn {m.turn_index + 1} ({m.sender}): {m.cleaned_body[:100]}..."
                        for m in selected_thread.messages[:-1]
                    ]
                    st.code("\n".join(prior_turns) if prior_turns else "No prior turns found")
                    previous_email_text = (
                        selected_thread.messages[-2].cleaned_body
                        if len(selected_thread.messages) >= 2
                        else ""
                    )
                else:
                    st.info("Benchmark corpus loading or not available. Use Direct Context Input.")

        st.write("")
        analyze_clicked = st.button("🔍  Analyze Email", type="primary", use_container_width=True)

        if analyze_clicked:
            with st.spinner("Processing multi-modal features and trajectory..."):
                res = engine.analyze(
                    subject=input_subject,
                    body=input_body,
                    sender=input_sender,
                    previous_email_text=previous_email_text if has_thread else None,
                )
                st.session_state["last_result"] = res
                st.session_state["session_analyzed_count"] += 1
                st.rerun()

    # ------------------ RIGHT COLUMN: Inspection Results ------------------
    with col_results:
        res = st.session_state.get("last_result")

        st.markdown(
            """
            <div class="workspace-header">
                <span class="workspace-title">Inspection Results</span>
                <span class="workspace-pill">Security Evaluation</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if res is None:
            # Concentric Radar / Biometric Scanner Empty State (Star Removed)
            st.markdown(
                """
                <div class="empty-state-card">
                    <div class="radar-graphic">
                        <svg width="84" height="84" viewBox="0 0 84 84" fill="none" style="filter: drop-shadow(0 0 16px rgba(99, 102, 241, 0.55));">
                            <circle cx="42" cy="42" r="38" stroke="#4F46E5" stroke-width="2" stroke-dasharray="8 5" opacity="0.7"/>
                            <circle cx="42" cy="42" r="28" stroke="#38BDF8" stroke-width="1.8" opacity="0.85"/>
                            <circle cx="42" cy="42" r="18" stroke="#6366F1" stroke-width="2.2"/>
                            <circle cx="42" cy="42" r="8" fill="#4F46E5" fill-opacity="0.35"/>
                            <path d="M 42 12 L 42 22 M 42 62 L 42 72 M 12 42 L 22 42 M 62 42 L 72 42" stroke="#38BDF8" stroke-width="2.2" stroke-linecap="round"/>
                        </svg>
                    </div>
                    <div class="empty-state-headline">Awaiting Email Submission</div>
                    <p class="empty-state-text">
                        Select one of the demonstration scenarios above or enter email content in the inspection workspace, then click <b>Analyze Email</b> to evaluate phishing risk and more.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            # 1. Main Security Verdict Banner
            fused = res["fused_verdict"]
            risk_level = fused["risk_level"]

            if risk_level == "HIGH":
                verdict_class = "verdict-banner-threat"
            elif risk_level == "MEDIUM":
                verdict_class = "verdict-banner-caution"
            else:
                verdict_class = "verdict-banner-safe"

            st.markdown(
                f"""
                <div class="{verdict_class}">
                    <div class="verdict-banner-title">{fused['status']} — {fused['confidence']:.1%} Confidence</div>
                    <p class="verdict-banner-body"><b>Primary Evaluation:</b> {fused['summary']}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # 2. Conversation Trajectory Analysis (if thread evaluated)
            t_res = res.get("thread_analysis")
            if t_res:
                st.markdown('<div class="preset-bar-title">Conversation Trajectory Analysis</div>', unsafe_allow_html=True)

                shift_status = t_res["status"]
                is_threat_shift = shift_status == "SUSPICIOUS INTENT SHIFT"
                is_pivot = shift_status == "UNVERIFIED INTENT PIVOT"

                if is_threat_shift:
                    marker_class = "timeline-marker-alert"
                elif is_pivot:
                    marker_class = "timeline-marker"
                else:
                    marker_class = "timeline-marker"

                st.markdown(
                    f"""
                    <div class="trajectory-box">
                        <div class="timeline-step">
                            <span class="timeline-marker">Turn t-1</span>
                            <div>
                                <div class="timeline-content-title">Established Thread Intent</div>
                                <div class="timeline-content-body">{t_res['previous_intent']}</div>
                            </div>
                        </div>
                        <div class="timeline-step">
                            <span class="{marker_class}">Turn t</span>
                            <div>
                                <div class="timeline-content-title">Incoming Message Intent & Trajectory</div>
                                <div class="timeline-content-body">
                                    <b>{t_res['current_intent']}</b> — {shift_status} (Continuity: {t_res['continuity_similarity']:.1%})
                                </div>
                            </div>
                        </div>
                        <div style="margin-top: 10px; font-size: 0.88rem; color: #E2E8F0; border-top: 1px solid #24334D; padding-top: 8px;">
                            {t_res['simple_explanation']}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # 3. Multi-Modal Technical Telemetry Grid
            st.markdown('<div class="preset-bar-title">Technical Telemetry & Indicators</div>', unsafe_allow_html=True)
            f = res["features"]

            st.markdown(
                f"""
                <div class="telemetry-grid">
                    <div class="telemetry-cell">
                        <div class="telemetry-label">Urgency Pressure</div>
                        <div class="telemetry-value">{int(f.get('urgency_score', 1))} / 10</div>
                    </div>
                    <div class="telemetry-cell">
                        <div class="telemetry-label">External Links</div>
                        <div class="telemetry-value">{int(f.get('num_links', 0))}</div>
                    </div>
                    <div class="telemetry-cell">
                        <div class="telemetry-label">SPF Verification</div>
                        <div class="telemetry-value">{f.get('spf_status', 'Pass')}</div>
                    </div>
                    <div class="telemetry-cell">
                        <div class="telemetry-label">DKIM Signature</div>
                        <div class="telemetry-value">{f.get('dkim_status', 'Pass')}</div>
                    </div>
                    <div class="telemetry-cell">
                        <div class="telemetry-label">Inference Latency</div>
                        <div class="telemetry-value">{res.get('latency_ms', 10.0)} ms</div>
                    </div>
                    <div class="telemetry-cell">
                        <div class="telemetry-label">Domain Trust</div>
                        <div class="telemetry-value">{'Flagged' if f.get('spf_status') == 'Fail' or f.get('dkim_status') == 'Fail' else 'Standard'}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # 4. Detected Threat Indicators & Keyword Signals
            evidence = res["explanation"].get("evidence_points", [])
            terms = res["explanation"].get("suspicious_terms", [])

            if evidence or terms:
                if evidence:
                    st.markdown('<div class="preset-bar-title">Identified Threat Indicators</div>', unsafe_allow_html=True)
                    for pt in evidence:
                        st.markdown(f'<div class="indicator-bullet">• {pt}</div>', unsafe_allow_html=True)

                if terms:
                    st.markdown('<div class="preset-bar-title" style="margin-top: 10px;">Identified High-Risk Terms</div>', unsafe_allow_html=True)
                    chips_html = "".join([f'<span class="chip">{term}</span>' for term in terms])
                    st.markdown(chips_html, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
