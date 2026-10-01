"""
Phishing Email Detection & Awareness Dashboard
Module: Content Analysis Engine
File: backend/services/content_analyzer.py

Performs rule-based psychological and semantic indicator detection on email subject and body,
identifying social engineering triggers such as urgency, fear, financial pressure, credential harvesting,
rewards, generic greetings, and typographic anomalies.
"""

import re

# Indicators and keyword categories
INDICATOR_CATEGORIES = {
    "urgency": [
        "immediately", "urgent", "act now", "action required", "within 24 hours",
        "expires today", "final notice", "hurry", "right now", "within 15 minutes",
        "emergency", "instant verification", "time-sensitive", "asap"
    ],
    "fear_threat": [
        "account will be suspended", "permanently deactivated", "legal escalation",
        "service termination", "unauthorized login", "unauthorized access", "compromised",
        "permanent closure", "locked", "failure to comply", "indefinitely", "suspension",
        "account suspended", "deactivated"
    ],
    "financial_pressure": [
        "outstanding balance", "invoice due", "wire transfer", "overdue balance",
        "customs surcharge", "settlement", "payment required", "tax refund",
        "billing dispute", "unpaid fee", "invoice", "payment overdue"
    ],
    "credential_request": [
        "verify your password", "confirm your credentials", "sign in to your microsoft",
        "validate your account", "enter your pin", "reset password", "domain credentials",
        "update credentials", "login details", "password was expired", "verify password",
        "verify your account", "confirm password", "enter credentials", "login to verify",
        "verify account"
    ],
    "reward_prize": [
        "you have won", "grand prize", "gift card", "selected as our winner",
        "claim your reward", "free delivery", "cash prize", "congratulations: you",
        "claim prize", "lottery winner"
    ],
    "personal_info_request": [
        "confirm your personal details", "social security number", "date of birth",
        "card number", "cvv", "billing address", "bank account number",
        "identity verification", "ssn", "confirm identity"
    ],
    "generic_greeting": [
        "dear valued customer", "dear user", "dear client", "dear employee",
        "dear member", "valued account holder", "attention: user", "dear customer"
    ]
}

def analyze_email_content(subject: str, body: str) -> dict:
    """
    Scans the subject and body for social engineering indicators.

    Returns:
        dict: {
            "content_risk_score": int (0-100),
            "findings": list[str],
            "detected_categories": dict[str, list[str]],
            "has_generic_greeting": bool,
            "uppercase_ratio": float,
            "exclamation_count": int,
            "subject_urgency": bool
        }
    """
    subject = subject or ""
    body = body or ""
    full_text = f"{subject}\n{body}".lower()
    
    findings = []
    detected = {}
    content_risk = 0

    # 1. Category keyword scanning
    for category, keywords in INDICATOR_CATEGORIES.items():
        matched = []
        for kw in keywords:
            # Word boundary matching where appropriate or phrase search
            if kw in full_text:
                matched.append(kw)
        if matched:
            detected[category] = matched

    # Weighting content indicators
    if "credential_request" in detected:
        findings.append(f"Direct credential request detected ({', '.join(detected['credential_request'][:3])}). This is a major phishing hallmark.")
        content_risk += 35

    if "fear_threat" in detected:
        findings.append(f"Coercive or threatening language detected ({', '.join(detected['fear_threat'][:2])}). Cybercriminals use fear to force hasty compliance.")
        content_risk += 25

    if "urgency" in detected:
        findings.append(f"Artificial urgency detected ({', '.join(detected['urgency'][:3])}). Attackers limit decision time to bypass critical thinking.")
        content_risk += 20

    if "financial_pressure" in detected:
        findings.append(f"Financial pressure or urgent transaction demand detected ({', '.join(detected['financial_pressure'][:2])}).")
        content_risk += 20

    if "personal_info_request" in detected:
        findings.append(f"Solicitation of sensitive personal or financial information ({', '.join(detected['personal_info_request'][:2])}).")
        content_risk += 25

    if "reward_prize" in detected:
        findings.append(f"Lure / prize incentive detected ({', '.join(detected['reward_prize'][:2])}). Classic baiting social engineering technique.")
        content_risk += 20

    has_generic_greeting = "generic_greeting" in detected
    if has_generic_greeting:
        findings.append(f"Impersonal / generic greeting detected ('{detected['generic_greeting'][0]}'). Mass phishing campaigns rarely know your real name.")
        content_risk += 10

    # 2. Subject urgency check
    subj_lower = subject.lower()
    subject_urgency = any(k in subj_lower for k in ["urgent", "action required", "immediate", "alert", "notice", "critical", "suspension", "overdue"])
    if subject_urgency:
        findings.append("Subject line engineered to provoke alarm or immediate reaction.")
        content_risk += 15

    # 3. Typographic anomalies (Uppercase ratio & excessive punctuation)
    total_letters = sum(c.isalpha() for c in body)
    upper_letters = sum(c.isupper() for c in body)
    uppercase_ratio = round((upper_letters / total_letters), 3) if total_letters > 0 else 0.0

    if uppercase_ratio > 0.25 and total_letters > 40:
        findings.append(f"High uppercase text ratio ({int(uppercase_ratio*100)}%), indicating shouting or aggressive pressure.")
        content_risk += 15

    exclamation_count = body.count("!") + subject.count("!")
    if exclamation_count >= 3:
        findings.append(f"Multiple exclamation marks ({exclamation_count}), typical in emotional manipulation.")
        content_risk += 10

    if not findings:
        findings.append("Email text exhibits neutral tone with no common social-engineering pressure words.")
        content_risk = 0

    return {
        "content_risk_score": min(content_risk, 100),
        "findings": findings,
        "detected_categories": detected,
        "has_generic_greeting": has_generic_greeting,
        "uppercase_ratio": uppercase_ratio,
        "exclamation_count": exclamation_count,
        "subject_urgency": subject_urgency
    }
