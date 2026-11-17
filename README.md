# MailZen — Threat Intelligence & Phishing Detection Platform

MailZen is an enterprise email security platform combining multi-modal phishing detection, intent extraction, and conversational intent-shift detection, trained and evaluated on **real-world email datasets**.


---

## 📁 Clean Project Architecture

```
rio/
├── data/
│   └── raw/
│       ├── real_phishing_dataset.csv     # 50,000 real-world emails (Phishing & Legitimate)
│       └── email_thread_details.csv      # Real-world multi-turn conversation threads
│
├── ml/
│   ├── extractor.py       # Automated email feature extractor (URLs, urgency, auth, domains)
│   ├── train_phishing.py  # Model trainer on 50,000 real emails (99.3% accuracy, 0.998 ROC-AUC)
│   ├── intent.py          # Email intent & sensitive action extraction
│   ├── threads.py         # Thread context reconstruction & conversational intent-shift detection
│   ├── explain.py         # Simple, plain-English explanation generator
│   └── engine.py          # Unified high-speed real-time inference engine (~7.8 ms latency)
│
├── models/
│   ├── phishing_model.joblib   # Trained real phishing detection model
│   └── intent_model.joblib     # Trained intent classification model
│
├── reports/
│   ├── phishing_metrics.json   # Evaluation metrics on 10,000 real test emails
│   └── evaluation_summary.json # Real-time latency & dataset benchmarks
│
├── tests/                 # Unit & integration tests
├── app.py                 # Unified, streamlined Streamlit web dashboard
├── run_ui.bat             # 1-click launcher for Windows
├── pyproject.toml         # Pytest configuration
└── requirements.txt       # Core project dependencies
```

---

## 🚀 Quick Start: Running the System

### 1. Set Up Environment
In Windows Command Prompt (`cmd`):
```cmd
cd /d "c:\Users\LENOVO\OneDrive\Desktop\rio"
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

### 2. Launch the Streamlit Web UI
```cmd
python -m streamlit run app.py
```
*(Or simply double-click **`run_ui.bat`** in the project folder).*

Open your browser to: **`http://localhost:8501`**

---

## 🎯 Key Capabilities & Research Objectives

1. **Multi-Feature Real Phishing Detection**:
   - Trained on 50,000 real-world emails (`real_phishing_dataset.csv`).
   - Combines TF-IDF text n-grams with automated multi-modal tabular features:
     - URL count & HTTPS protocol detection
     - Domain and subdomain structure
     - SPF / DKIM / DMARC authentication status
     - Linguistic urgency scoring (1–10 scale)
     - High-risk security keyword density
     - Attachment presence and file extension risk (.pdf, .docx, .zip, .exe)
   - **Performance on 10,000 real test emails**:
     - **Accuracy**: `99.32%`
     - **Precision**: `99.85%`
     - **Recall**: `98.48%`
     - **ROC-AUC**: `0.9982`
     - **False Positive Rate**: `0.10%`

2. **Conversational Intent-Shift & Hijacking Detection**:
   - Ingests real multi-turn conversation threads from `email_thread_details.csv`.
   - Checks whether an incoming reply continues an existing thread.
   - Detects **Suspicious Intent Shifts (Business Email Compromise / Thread Hijacking)**: flags when a thread starts with safe collaboration (e.g. meeting scheduling, project reviews) and suddenly pivots to urgent sensitive demands (e.g. credentials, unauthorized wire transfers).

3. **Simple, Plain-English Explainability**:
   - Generates simple 1–2 sentence explanations answering clearly *why* an email was flagged as phishing, without confusing machine learning jargon.
   - Lists specific risk flags (e.g. authentication failure, coercive deadlines, unverified external links).

4. **Real-Time Speed**:
   - Measured average inference latency of **~7.8 ms** per email, easily satisfying sub-second real-time gateway requirements.

---

## 🧪 Testing & Benchmarks

Run the complete test suite (13 tests):
```cmd
python -m pytest
```

Run real-time latency and thread benchmarks:
```cmd
python -m evaluation.benchmark
```

Retrain the real phishing detection model:
```cmd
python -m ml.train_phishing
```
