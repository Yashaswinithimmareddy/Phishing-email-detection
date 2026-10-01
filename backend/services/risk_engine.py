"""
Phishing Email Detection & Awareness Dashboard
Module: Risk Scoring & Explainability Engine
File: backend/services/risk_engine.py

Calculates comprehensive phishing risk scores (0-100), performs calibrated risk classification,
generates explainable cybersecurity findings, maps to MITRE ATT&CK framework techniques,
and produces actionable defensive recommendations.
"""

from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import extract_urls_from_text, analyze_url
from backend.services.attachment_analyzer import analyze_attachment

def classify_risk_score(score: int) -> str:
    """
    Calibrates numerical risk score into standard cybersecurity triage tiers.
    """
    if score <= 20:
        return "SAFE / LOW RISK"
    elif score <= 40:
        return "MODERATE RISK"
    elif score <= 70:
        return "SUSPICIOUS"
    else:
        return "HIGH RISK / LIKELY PHISHING"

def calculate_phishing_score(
    sender: str, 
    subject: str, 
    body: str, 
    urls: str = "", 
    attachment_name: str = "",
    display_name: str = "",
    ml_probability: float = None
) -> dict:
    """
    Executes the complete multi-vector defensive analysis pipeline.

    Returns:
        dict: Complete structured analysis with scores, explanations, and mitigation actions.
    """
    sender = "" if sender is None or not isinstance(sender, str) else str(sender).strip()
    subject = "" if subject is None or not isinstance(subject, str) else str(subject).strip()
    body = "" if body is None or not isinstance(body, str) else str(body).strip()
    urls = "" if urls is None or not isinstance(urls, str) else str(urls).strip()
    attachment_name = "" if attachment_name is None or not isinstance(attachment_name, str) else str(attachment_name).strip()
    display_name = "" if display_name is None or not isinstance(display_name, str) else str(display_name).strip()

    # 1. Run Component Analyzers
    sender_analysis = analyze_sender(sender, display_name=display_name)
    content_analysis = analyze_email_content(subject, body)
    attachment_analysis = analyze_attachment(attachment_name)

    # Extract all URLs
    extracted_urls = extract_urls_from_text(body)
    if urls and urls.strip() and urls.strip() not in extracted_urls:
        extracted_urls.append(urls.strip())

    url_analyses = [analyze_url(u) for u in extracted_urls]

    # Max risk from attached URLs
    max_url_risk = max([u["url_risk_score"] for u in url_analyses], default=0)

    # 2. Rule-Based Scoring Matrix
    rule_score = 0
    why_explanations = []
    mitre_techniques = []

    # Sender weight (up to 25 pts)
    if sender_analysis["sender_risk_score"] > 0:
        sender_pts = min(int(sender_analysis["sender_risk_score"] * 0.30), 25)
        rule_score += sender_pts
        for f in sender_analysis["sender_findings"]:
            if "standard" not in f.lower():
                why_explanations.append(f"Sender Pattern: {f}")
        if sender_analysis["display_name_mismatch"] or sender_analysis["sender_risk_score"] >= 30:
            mitre_techniques.append({"id": "T1583.001", "name": "Domains / Typosquatting"})

    # Content - Credential Harvesting (up to 30 pts)
    if "credential_request" in content_analysis["detected_categories"]:
        rule_score += 30
        why_explanations.append("Credential Request: Email solicits password or identity authentication.")
        mitre_techniques.append({"id": "T1566", "name": "Phishing / Credential Harvesting"})

    # Content - Fear / Coercive Threat (up to 15 pts)
    if "fear_threat" in content_analysis["detected_categories"]:
        rule_score += 15
        why_explanations.append("Intimidation / Fear: Threats of account suspension or penalty to rush compliance.")

    # Content - Urgency (up to 15 pts)
    if "urgency" in content_analysis["detected_categories"] or content_analysis["subject_urgency"]:
        rule_score += 15
        why_explanations.append("Artificial Urgency: Language designed to bypass deliberation.")

    # Content - Financial / Reward (up to 15 pts)
    if "financial_pressure" in content_analysis["detected_categories"]:
        rule_score += 15
        why_explanations.append("Financial Trigger: Unsolicited invoice, wire transfer, or overdue fee pressure.")
    if "reward_prize" in content_analysis["detected_categories"]:
        rule_score += 15
        why_explanations.append("Reward / Baiting: Unrealistic lottery or prize lure detected.")

    # Content - Generic Greeting (up to 5 pts)
    if content_analysis["has_generic_greeting"]:
        rule_score += 5
        why_explanations.append("Generic Greeting: Lacks personalized salutation (typical in bulk campaigns).")

    # Content - Typographic Anomalies (up to 10 pts)
    if content_analysis["uppercase_ratio"] > 0.25 or content_analysis["exclamation_count"] >= 3:
        rule_score += 10
        why_explanations.append("Linguistic Anomalies: Elevated uppercase or exclamation density.")

    # URL Risk (up to 35 pts)
    if max_url_risk > 0:
        url_pts = min(int(max_url_risk * 0.40), 35)
        rule_score += url_pts
        for ua in url_analyses:
            if ua["url_risk_score"] >= 20:
                for f in ua["findings"]:
                    why_explanations.append(f"Suspicious URL ({ua['hostname']}): {f}")
        mitre_techniques.append({"id": "T1566.002", "name": "Spearphishing Link"})

    # Attachment Risk (up to 45 pts)
    if attachment_analysis["attachment_risk_score"] > 0:
        att_pts = min(int(attachment_analysis["attachment_risk_score"] * 0.45), 45)
        rule_score += att_pts
        for f in attachment_analysis["findings"]:
            if "standard document" not in f.lower():
                why_explanations.append(f"Attachment Risk: {f}")
        if attachment_analysis["is_suspicious"]:
            mitre_techniques.append({"id": "T1566.001", "name": "Spearphishing Attachment"})
            mitre_techniques.append({"id": "T1204.002", "name": "User Execution: Malicious File"})

    # Clamp rule score between 0 and 100
    rule_score = min(max(rule_score, 0), 100)

    # 3. Hybrid Combination (if ML Probability is provided)
    if ml_probability is not None:
        ml_score = int(round(ml_probability * 100))
        # Defensive Security Principle: High-confidence heuristic indicators (credential harvesting,
        # raw IP URLs, executable attachments) must not be suppressed by statistical NLP dilution.
        if rule_score >= 70:
            final_score = max(rule_score, int(round(0.60 * rule_score + 0.40 * ml_score)))
        elif rule_score >= 40:
            final_score = int(round(0.60 * rule_score + 0.40 * ml_score))
        else:
            final_score = int(round(0.50 * rule_score + 0.50 * ml_score))
        mode = "Hybrid (Rule-Based + ML Model)"
    else:
        final_score = rule_score
        mode = "Rule-Based Engine"

    final_score = min(max(final_score, 0), 100)
    classification = classify_risk_score(final_score)

    if not why_explanations:
        why_explanations.append("Email presents standard corporate communication traits without social-engineering pressure.")

    # 4. Generate Security Recommendations
    recommendations = []
    if final_score >= 41:
        recommendations.append("Do NOT click on any embedded links or paste them into your browser.")
        recommendations.append("Do NOT open or download any unexpected attachments.")
        recommendations.append("Never enter passwords, PINs, or financial details on pages reached via email.")
        recommendations.append("Verify the sender's identity through an out-of-band channel (e.g., official directory).")
        recommendations.append("Report this message immediately to your internal SOC / Security Incident Response team.")
    elif final_score >= 21:
        recommendations.append("Exercise caution before interacting with this email.")
        recommendations.append("Hover over links (without clicking) to inspect destination domains.")
        recommendations.append("Confirm unexpected transaction or invoice requests with the sender directly.")
    else:
        recommendations.append("Email exhibits low risk indicators. Follow standard security hygiene.")
        recommendations.append("Navigate to organization services using verified bookmarks or official apps.")

    # Deduplicate MITRE tags
    unique_mitre = []
    seen_ids = set()
    for m in mitre_techniques:
        if m["id"] not in seen_ids:
            seen_ids.add(m["id"])
            unique_mitre.append(m)

    return {
        "risk_score": final_score,
        "rule_score": rule_score,
        "ml_probability": ml_probability,
        "detection_mode": mode,
        "classification": classification,
        "why_explanations": why_explanations,
        "recommendations": recommendations,
        "mitre_techniques": unique_mitre,
        "sender_analysis": sender_analysis,
        "content_analysis": content_analysis,
        "url_analyses": url_analyses,
        "attachment_analysis": attachment_analysis
    }
