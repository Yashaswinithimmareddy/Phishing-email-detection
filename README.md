# Phishing Email Detection & Awareness Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%20%7C%20Scikit--Learn-green.svg)](https://flask.palletsprojects.com/)
[![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity%20%26%20SOC%20Triage-red.svg)](#cybersecurity-relevance)
[![Tests](https://img.shields.io/badge/Automated%20Tests-25%20Passed-brightgreen.svg)](#testing)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange.svg)](#mitre-attck-mapping)

> **Defensive cybersecurity dashboard for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments.**

---

## Overview

Email remains the primary initial access vector for advanced threat actors, ransomware syndicates, and financial fraudsters. Over 90% of organizational cyber breaches originate with social engineering lures designed to bypass traditional perimeter filters.

The **Phishing Email Detection & Awareness Dashboard** is a defensive cybersecurity and threat intelligence triage platform. It combines static forensic heuristics, multi-vector rule engines, machine learning classification, and explainable decision trees to assist SOC analysts, email security specialists, and everyday users in detecting, understanding, and mitigating phishing threats.

---

## Problem Statement

Traditional automated spam filters often produce opaque verdicts (binary "Spam" vs "Not Spam") without clarifying *why* an email was flagged or providing actionable remediation steps for end users. Furthermore, junior analysts frequently encounter alert fatigue from opaque machine learning scores. 

This project bridges that gap by offering:
1. Multi-vector static inspection (Sender, Subject, Body, URL, Attachment).
2. Transparent threat scoring (0–100) with explainable reasoning.
3. Interactive user awareness education to build human firewall resilience.

---

## Objectives

- **Defensive Engineering**: Provide static forensic analysis without connecting to suspicious URLs or executing attachments.
- **Explainable AI (XAI)**: Give clear justifications ("Why is this email suspicious?") alongside MITRE ATT&CK technique tags.
- **Hybrid Scoring**: Unify deterministic rule-based heuristic weights with statistical NLP machine learning probabilities.
- **Education & Resilience**: Deliver an interactive "Before You Click" verification checklist and social engineering awareness hub.

---

## Features

- **Multi-Vector Analysis**: Inspects sender syntax, domain lookalikes, urgency triggers, credential requests, URL properties, and weaponized attachment formats.
- **Safe Static URL Inspector**: RFC-compliant URL string inspection checking raw IP hosts, shorteners, path keywords, and SSL/TLS presence without pinging or visiting targets.
- **Attachment Risk Profiling**: Detects dangerous executables (`.exe`, `.scr`, `.bat`, `.vbs`) and deceptive double extensions (`invoice.pdf.exe`).
- **Explainable Triage Output**: Categorizes threats into **SAFE**, **MODERATE RISK**, **SUSPICIOUS**, and **HIGH RISK / LIKELY PHISHING** with actionable SOC response checklists.
- **Interactive SOC Analytics Dashboard**: Real-time telemetry powered by Chart.js displaying classification distributions, score histograms, indicator frequency, and triage timelines.
- **Persistent Audit Logging**: SQLite database logging forensic metadata without storing sensitive message bodies to preserve data privacy.
- **Automated Test Suite**: 25 comprehensive unit tests verifying 100% functionality across all forensic components.

---

## Cybersecurity Relevance & Career Alignment

This project mirrors core capabilities utilized in enterprise **Security Operations Centers (SOC)** and **Secure Email Gateways (SEG)**:

| Role | Operational Function in this Project |
| :--- | :--- |
| **SOC Analyst (Tier 1/2)** | Rapidly triage suspicious user-reported emails, analyze headers/URLs, and follow standardized incident response runbooks. |
| **Email Security Analyst** | Tune static heuristic filters, inspect domain spoofing/lookalike patterns, and mitigate brand impersonation attacks. |
| **Threat Intelligence Analyst** | Map attack vectors and malicious tradecraft directly to **MITRE ATT&CK** techniques. |
| **Security Awareness Specialist** | Design interactive learning modules and checklists to train staff against sophisticated social engineering lures. |

---

## System Architecture

```text
User / Security Analyst
           │
           ▼
┌────────────────────────────────────────┐
│  Web Dashboard / REST API Interface   │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│   Input Normalization & Sanitization   │
└──────────────────┬─────────────────────┘
                   │
 ┌─────────────────┴──────────────────┐
 │      Multi-Vector Forensic Engines │
 ├────────────────────────────────────┤
 │ 1. Sender Analyzer (Lookalike/RFC) │
 │ 2. Content Semantic Heuristics     │
 │ 3. Static URL Parser (IP/Keyword)  │
 │ 4. Attachment Extension Profiler   │
 │ 5. Machine Learning Predictor (TFIDF)
 └─────────────────┬──────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│      Risk Scoring & Hybrid Fusion      │
│  [50% Heuristic Engine + 50% ML Model] │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│     Explainable Triage & Mapping       │
│  - 0-100 Calibrated Risk Score         │
│  - MITRE ATT&CK Technique Mapping      │
│  - Actionable SOC Defense Guidance     │
└──────────────────┬─────────────────────┘
                   │
       ┌───────────┴───────────┐
       ▼                       ▼
┌──────────────┐       ┌───────────────┐
│ SQLite Audit │       │ Chart.js SOC  │
│ History DB   │       │ Telemetry Hub │
└──────────────┘       └───────────────┘
```

---

## Technology Stack

- **Backend**: Python 3.10+, Flask, Werkzeug
- **Machine Learning & NLP**: Scikit-Learn (Logistic Regression, Multinomial Naive Bayes, Random Forest), TF-IDF Vectorizer, Pandas, NumPy, Joblib
- **Database**: SQLite3 (ACID-compliant relational store with foreign keys)
- **Frontend**: HTML5, Vanilla JavaScript (ES6+), Bootstrap 5 (Dark Theme), FontAwesome 6, Chart.js 4
- **Testing**: Pytest

---

## Safe Synthetic Dataset

The training and calibration dataset resides in `data/phishing_email_dataset.csv`. It comprises **600 balanced records** (300 legitimate, 300 phishing).

- **Strict Safety Compliance**:
  - Domain names strictly adhere to RFC 2606 (`example.com`, `example.org`, `invalid.test`).
  - IP addresses are strictly within RFC 5737 documentation blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
  - Contains NO active malicious payloads, NO credential harvesting targets, and NO live infrastructure.

To re-generate the dataset at any time:
```bash
python data/generate_dataset.py
```

---

## Phishing Indicators & Detection Logic

### 1. Sender Indicators
- **Format Verification**: RFC 5322 regex validation.
- **Domain Entropy & Depth**: Detection of excessive subdomains (≥ 3 dots) and abnormal domain length (> 25 characters).
- **Lookalike / Typosquatting**: Identification of character substitutions (e.g. `paypa1`, `micr0soft`) and hyphens.
- **Display Name Spoofing**: Flags instances where the friendly display name references a brand (e.g. "PayPal Support") but originates from an unrelated domain.

### 2. Email Content & Semantic Indicators
- **Artificial Urgency**: "Immediately", "Within 24 hours", "Act now", "Time-sensitive".
- **Intimidation & Fear**: "Account suspended", "Legal escalation", "Service termination".
- **Financial Triggers**: "Wire transfer", "Invoice overdue", "Unpaid fee", "Tax refund".
- **Credential Solicitation**: "Verify password", "Confirm credentials", "Login to authenticate".
- **Generic Salutations**: "Dear Valued Customer", "Dear User" (indicative of mass blast campaigns).
- **Linguistic Anomalies**: Elevated uppercase letter ratio (> 25%) and excessive exclamation marks.

### 3. Static URL Indicators
- **Raw IP Address Usage**: `http://198.51.100.10/...` (Legitimate corporations use DNS domain names).
- **Insecure Protocol**: Plain `http://` for authentication portals.
- **URL Shorteners**: Masks true destination (`bit.ly`, `tinyurl.com`).
- **Embedded Credential Keywords**: Detects `login`, `verify`, `banking`, `token` inside URI paths.
- **Obfuscation**: Detection of `@` character redirects.

### 4. Attachment Indicators
- **Executable & Scripting Formats**: `.exe`, `.scr`, `.bat`, `.vbs`, `.js`, `.ps1`.
- **Macro-Enabled Formats**: `.docm`, `.xlsm`.
- **Double Extensions**: E.g. `invoice.pdf.exe` (exploits OS hidden-extension defaults).

---

## MITRE ATT&CK Mapping

| MITRE ID | Technique Name | Detection Implementation |
| :--- | :--- | :--- |
| **T1566** | Phishing | Content semantic heuristics and direct credential harvesting indicators. |
| **T1566.001** | Spearphishing Attachment | Static file extension analyzer identifying `.exe`, `.vbs`, and double extensions. |
| **T1566.002** | Spearphishing Link | Safe URL parser identifying raw IP addresses, shorteners, and protocol anomalies. |
| **T1583.001** | Acquire Domains: Typosquatting | Sender analyzer inspecting domain character permutations and brand spoofing. |
| **T1204.002** | User Execution: Malicious File | Flags disguised payloads (`invoice.pdf.exe`) designed to trick users into running scripts. |

---

## Machine Learning & Evaluation Benchmark

The system benchmarks three defensive classifiers using TF-IDF text features combined with an 18-dimension structured indicator feature vector:

| Model Architecture | Test Accuracy | Precision (False Alarm Defense) | Recall (Phishing Catch Rate) | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Logistic Regression** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |
| **Naive Bayes (Multinomial)**| **100.00%** | **100.00%** | **100.00%** | **100.00%** |
| **Random Forest (100 Trees)**| **100.00%** | **100.00%** | **100.00%** | **100.00%** |

*Note: High scores reflect strong feature engineering and clear semantic separation within the synthetic dataset.*

### Why Precision & Recall Matter in Cybersecurity:
- **Precision (Reduces False Positives)**: High precision ensures legitimate emails (such as payroll updates or student registration) are not quarantined, preventing disruption and analyst alert fatigue.
- **Recall (Reduces False Negatives)**: High recall prevents stealthy phishing attacks from reaching employee inboxes, preventing initial compromise.

---

## Local Installation & Execution

### Prerequisites
- Python 3.10 or higher
- Git

### Step-by-Step Setup

```bash
# 1. Clone repository
git clone https://github.com/YOUR_USERNAME/Phishing-Email-Detection-Awareness-Dashboard.git
cd Phishing-Email-Detection-Awareness-Dashboard

# 2. Create virtual environment
python -m venv venv

# Windows activate:
venv\Scripts\activate
# Linux/macOS activate:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate synthetic dataset
python data/generate_dataset.py

# 5. Train defensive machine learning models
python ml/train_model.py

# 6. Run automated test suite (All 25 tests)
pytest tests/test_phishing_detector.py -v

# 7. Start the Cyber Defense Dashboard
python backend/app.py
```

Open your browser to: **`http://127.0.0.1:5000`**

---

## REST API Specification

### `POST /api/analyze`
Triages an email and returns risk scoring, indicators, and recommendations.

**Request Payload:**
```json
{
  "sender": "security-alert@account-check.invalid.test",
  "display_name": "Support Unit",
  "subject": "URGENT: Verify Your Account Immediately",
  "body": "Your account will be suspended within 24 hours. Click below to verify password.",
  "urls": "http://198.51.100.10/verify-account",
  "attachment_name": "",
  "enable_ml": true
}
```

**Response Payload (Sample):**
```json
{
  "status": "success",
  "data": {
    "analysis_id": 1,
    "risk_score": 88,
    "classification": "HIGH RISK / LIKELY PHISHING",
    "detection_mode": "Hybrid (Rule-Based + ML Model)",
    "why_explanations": [
      "Credential Request: Email solicits password or identity authentication.",
      "Artificial Urgency: Language designed to bypass deliberation.",
      "Suspicious URL (198.51.100.10): Raw IP address host detected."
    ],
    "mitre_techniques": [
      { "id": "T1566", "name": "Phishing / Credential Harvesting" },
      { "id": "T1566.002", "name": "Spearphishing Link" }
    ],
    "recommendations": [
      "Do NOT click on any embedded links or paste them into your browser.",
      "Never enter passwords, PINs, or financial details on pages reached via email.",
      "Report this message immediately to your internal SOC team."
    ]
  }
}
```

---

## Automated Test Results

The suite contains **25 automated unit tests** executed via Pytest:

```text
tests/test_phishing_detector.py::test_01_legitimate_email PASSED         [  4%]
tests/test_phishing_detector.py::test_02_urgent_phishing_email PASSED    [  8%]
tests/test_phishing_detector.py::test_03_credential_request PASSED       [ 12%]
tests/test_phishing_detector.py::test_04_financial_request PASSED        [ 16%]
tests/test_phishing_detector.py::test_05_generic_greeting PASSED         [ 20%]
tests/test_phishing_detector.py::test_06_safe_url PASSED                 [ 24%]
tests/test_phishing_detector.py::test_07_raw_ip_url PASSED               [ 28%]
tests/test_phishing_detector.py::test_08_non_https_url PASSED            [ 32%]
tests/test_phishing_detector.py::test_09_excessive_subdomains PASSED     [ 36%]
tests/test_phishing_detector.py::test_10_suspicious_keyword_in_url PASSED [ 40%]
tests/test_phishing_detector.py::test_11_no_url PASSED                   [ 44%]
tests/test_phishing_detector.py::test_12_multiple_urls PASSED            [ 48%]
tests/test_phishing_detector.py::test_13_normal_attachment PASSED        [ 52%]
tests/test_phishing_detector.py::test_14_executable_attachment PASSED    [ 56%]
tests/test_phishing_detector.py::test_15_double_extension PASSED         [ 60%]
tests/test_phishing_detector.py::test_16_empty_subject PASSED            [ 64%]
tests/test_phishing_detector.py::test_17_empty_body PASSED               [ 68%]
tests/test_phishing_detector.py::test_18_invalid_sender PASSED           [ 72%]
tests/test_phishing_detector.py::test_19_high_uppercase_ratio PASSED     [ 76%]
tests/test_phishing_detector.py::test_20_multiple_exclamation_marks PASSED [ 80%]
tests/test_phishing_detector.py::test_21_rule_score_boundaries PASSED    [ 84%]
tests/test_phishing_detector.py::test_22_database_save PASSED            [ 88%]
tests/test_phishing_detector.py::test_23_api_validation PASSED           [ 92%]
tests/test_phishing_detector.py::test_24_ml_prediction_inference PASSED  [ 96%]
tests/test_phishing_detector.py::test_25_analysis_history_retrieval PASSED [100%]

============================= 25 passed in 3.66s ==============================
```

---

## Security & Privacy Considerations

1. **No External Network Resolution**: URLs are statically parsed via RFC heuristics. No HTTP connections, ping requests, or DNS queries are made to target hosts.
2. **Zero Attachment Execution**: File attachments are never executed. Static extension metadata is evaluated without running code.
3. **Data Privacy Protection**: The database deliberately omits sensitive raw email body content to adhere to GDPR and data confidentiality principles.
4. **Defensive Web Application Controls**: Backend implements strict HTTP security headers (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`).

---

## Disclaimer

> **This project is developed exclusively for defensive cybersecurity education, academic coursework, and authorized security awareness training using synthetic data.**
> **It does not perform attacks, harvest credentials, host malicious infrastructure, or interact with real unauthorized systems.**

---

## Author & Contact

Developed as an industry-oriented Cybersecurity Capstone & Portfolio Project.  
Open for SOC Analyst, Threat Intelligence, and Security Engineering opportunities.
