"""
Phishing Email Detection & Awareness Dashboard
Module: Email Feature Engineering & Preprocessing
File: backend/services/feature_extractor.py

Extracts 18+ rich, cybersecurity-aligned linguistic, structural, and indicator features
from raw email metadata and text without destroying investigative forensic artifacts.
"""

import re
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content, INDICATOR_CATEGORIES
from backend.services.url_analyzer import extract_urls_from_text, analyze_url
from backend.services.attachment_analyzer import analyze_attachment

def preprocess_text(text: str) -> str:
    """
    Cleans text for machine learning while preserving key cybersecurity indicators.
    Avoids aggressive stripping of punctuation or symbols because characters like '!'
    and '@' are critical forensic signals in phishing detection.
    """
    if not text:
        return ""
    # Normalize excessive whitespace but preserve capitalization & special symbols
    cleaned = re.sub(r"\s+", " ", text).strip()
    return cleaned

def extract_email_features(sender: str = "", subject: str = "", body: str = "", urls: str = "", attachment_name: str = "") -> dict:
    """
    Transforms raw email parameters into a structured, numerical and boolean feature set
    for rule-based scoring and machine learning pipelines.

    Returns:
        dict: Detailed feature dictionary containing 18 distinct indicators.
    """
    sender = "" if sender is None or not isinstance(sender, str) else str(sender).strip()
    subject = "" if subject is None or not isinstance(subject, str) else str(subject).strip()
    body = "" if body is None or not isinstance(body, str) else str(body).strip()
    urls = "" if urls is None or not isinstance(urls, str) else str(urls).strip()
    attachment_name = "" if attachment_name is None or not isinstance(attachment_name, str) else str(attachment_name).strip()

    # Run modular analyzers
    sender_res = analyze_sender(sender)
    content_res = analyze_email_content(subject, body)
    attachment_res = analyze_attachment(attachment_name)

    # URL extraction: combine urls argument and any URLs embedded in the body
    extracted_urls = extract_urls_from_text(body)
    if urls and urls not in extracted_urls:
        extracted_urls.append(urls.strip())

    url_analyses = [analyze_url(u) for u in extracted_urls]
    
    # Feature calculations
    detected_cats = content_res.get("detected_categories", {})
    urgent_keyword_count = len(detected_cats.get("urgency", []))
    credential_keyword_count = len(detected_cats.get("credential_request", []))
    financial_keyword_count = len(detected_cats.get("financial_pressure", []))
    threat_keyword_count = len(detected_cats.get("fear_threat", []))

    url_count = len(url_analyses)
    suspicious_url_count = sum(1 for ua in url_analyses if ua["url_risk_score"] >= 30)
    has_ip_url = int(any(ua["is_ip_address"] for ua in url_analyses))
    has_shortened_url_pattern = int(any(ua["is_shortened"] for ua in url_analyses))

    features = {
        "urgent_keyword_count": urgent_keyword_count,
        "credential_keyword_count": credential_keyword_count,
        "financial_keyword_count": financial_keyword_count,
        "threat_keyword_count": threat_keyword_count,
        "url_count": url_count,
        "suspicious_url_count": suspicious_url_count,
        "has_ip_url": has_ip_url,
        "has_shortened_url_pattern": has_shortened_url_pattern,
        "sender_domain_length": sender_res["domain_length"],
        "subdomain_count": sender_res["subdomain_count"],
        "suspicious_attachment": int(attachment_res["is_suspicious"]),
        "generic_greeting": int(content_res["has_generic_greeting"]),
        "contains_password_request": int("credential_request" in detected_cats),
        "contains_personal_info_request": int("personal_info_request" in detected_cats),
        "exclamation_count": content_res["exclamation_count"],
        "uppercase_ratio": content_res["uppercase_ratio"],
        "body_length": len(body),
        "subject_length": len(subject)
    }

    return features
