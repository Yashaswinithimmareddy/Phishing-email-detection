"""
Phishing Email Detection & Awareness Dashboard
Test Suite: Defensive Security Triage Engine
File: tests/test_phishing_detector.py

Comprehensive 25-Point Automated Unit Test Suite covering:
1. Legitimate email
2. Urgent phishing-style email
3. Credential request
4. Financial request
5. Generic greeting
6. Safe URL
7. Raw IP URL
8. Non-HTTPS URL
9. Excessive subdomains
10. Suspicious keyword in URL
11. No URL
12. Multiple URLs
13. Normal attachment
14. Executable attachment
15. Double extension
16. Empty subject
17. Empty body
18. Invalid sender
19. High uppercase ratio
20. Multiple exclamation marks
21. Rule-score boundary calibration
22. Database save
23. API validation
24. ML prediction inference
25. Analysis-history retrieval
"""

import os
import sys
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_url, extract_urls_from_text
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.risk_engine import calculate_phishing_score, classify_risk_score
from backend.models.database import init_db, save_analysis, get_recent_analyses, get_analysis_by_id
from backend.app import app
from ml.predict import PhishingPredictor

# Initialize test database
init_db()

# TEST 1: Legitimate Email
def test_01_legitimate_email():
    """Scenario 1: Standard informational email with benign traits."""
    sender = "registrar@university.example.edu"
    subject = "Academic Schedule Update"
    body = "Dear Student, the updated schedule is now online. Have a great semester."
    result = calculate_phishing_score(sender, subject, body, "", "")
    assert result["risk_score"] <= 20
    assert "SAFE" in result["classification"]

# TEST 2: Urgent Phishing-Style Email
def test_02_urgent_phishing_email():
    """Scenario 2: High urgency language provoking immediate panic."""
    sender = "security-alert@account-check.invalid.test"
    subject = "URGENT: Act now to prevent suspension"
    body = "Your account will be suspended within 24 hours immediately. Act now!"
    result = calculate_phishing_score(sender, subject, body, "", "")
    assert result["risk_score"] >= 20
    assert any("urgency" in exp.lower() or "sender" in exp.lower() for exp in result["why_explanations"])

# TEST 3: Credential Request
def test_03_credential_request():
    """Scenario 3: Direct solicitation of password / login credentials."""
    content = analyze_email_content("Security Notice", "Please verify your password and confirm credentials immediately.")
    assert "credential_request" in content["detected_categories"]
    assert content["content_risk_score"] >= 30

# TEST 4: Financial Request
def test_04_financial_request():
    """Scenario 4: Demands for wire transfers or overdue invoice payments."""
    content = analyze_email_content("Billing Notice", "Outstanding balance due. Execute the wire transfer today.")
    assert "financial_pressure" in content["detected_categories"]
    assert content["content_risk_score"] >= 20

# TEST 5: Generic Greeting
def test_05_generic_greeting():
    """Scenario 5: Impersonal mass phishing salutation."""
    content = analyze_email_content("Notice", "Dear Valued Customer, please review our terms.")
    assert content["has_generic_greeting"] is True
    assert "generic_greeting" in content["detected_categories"]

# TEST 6: Safe URL
def test_06_safe_url():
    """Scenario 6: Legitimate HTTPS URL with standard domain."""
    url_res = analyze_url("https://campus.example.edu/schedule")
    assert url_res["url_risk_score"] <= 10
    assert url_res["is_https"] is True
    assert url_res["is_ip_address"] is False

# TEST 7: Raw IP URL
def test_07_raw_ip_url():
    """Scenario 7: Naked IPv4 address host instead of registered domain."""
    url_res = analyze_url("http://198.51.100.10/verify-account")
    assert url_res["is_ip_address"] is True
    assert url_res["url_risk_score"] >= 45

# TEST 8: Non-HTTPS URL
def test_08_non_https_url():
    """Scenario 8: Plain unencrypted HTTP protocol."""
    url_res = analyze_url("http://insecure-portal.example.com/login")
    assert url_res["is_https"] is False
    assert any("HTTP" in f for f in url_res["findings"])

# TEST 9: Excessive Subdomains
def test_09_excessive_subdomains():
    """Scenario 9: Multiple subdomains used to evade filters."""
    url_res = analyze_url("https://verify.security.login.portal.example.com/auth")
    assert url_res["subdomain_count"] >= 3
    assert url_res["url_risk_score"] >= 20

# TEST 10: Suspicious Keyword in URL
def test_10_suspicious_keyword_in_url():
    """Scenario 10: URL path containing login/banking keywords."""
    url_res = analyze_url("https://example.com/banking/account-verify/token")
    assert len(url_res["suspicious_keywords_found"]) >= 2
    assert url_res["url_risk_score"] >= 20

# TEST 11: No URL
def test_11_no_url():
    """Scenario 11: Email with no URLs."""
    extracted = extract_urls_from_text("This message contains pure text with no links.")
    assert len(extracted) == 0

# TEST 12: Multiple URLs
def test_12_multiple_urls():
    """Scenario 12: Multiple URLs embedded across body text."""
    body = "Visit http://example.com/link1 and https://example.org/link2 for updates."
    extracted = extract_urls_from_text(body)
    assert len(extracted) == 2

# TEST 13: Normal Attachment
def test_13_normal_attachment():
    """Scenario 13: Benign PDF / document attachment."""
    att = analyze_attachment("annual_report_2026.pdf")
    assert att["is_suspicious"] is False
    assert att["attachment_risk_score"] <= 10

# TEST 14: Executable Attachment
def test_14_executable_attachment():
    """Scenario 14: Dangerous direct executable (.exe / .scr)."""
    att = analyze_attachment("software_update.exe")
    assert att["is_suspicious"] is True
    assert att["attachment_risk_score"] >= 60

# TEST 15: Double Extension
def test_15_double_extension():
    """Scenario 15: Weaponized double extension disguising executable."""
    att = analyze_attachment("invoice_receipt.pdf.exe")
    assert att["is_double_extension"] is True
    assert att["attachment_risk_score"] >= 80

# TEST 16: Empty Subject
def test_16_empty_subject():
    """Scenario 16: Robust handling of missing subject line."""
    result = calculate_phishing_score("admin@example.com", "", "Body text only.")
    assert isinstance(result["risk_score"], int)

# TEST 17: Empty Body
def test_17_empty_body():
    """Scenario 17: Robust handling of missing body."""
    result = calculate_phishing_score("admin@example.com", "Important notification", "")
    assert isinstance(result["risk_score"], int)

# TEST 18: Invalid Sender Email
def test_18_invalid_sender():
    """Scenario 18: Malformed sender string without @ or valid domain."""
    sender_res = analyze_sender("not-an-email-address")
    assert sender_res["sender_risk_score"] >= 30
    assert any("Invalid" in f for f in sender_res["sender_findings"])

# TEST 19: High Uppercase Ratio
def test_19_high_uppercase_ratio():
    """Scenario 19: Aggressive all-caps text shouting at recipient."""
    content = analyze_email_content("URGENT", "PLEASE BE ADVISED THIS IS A MANDATORY EMERGENCY NOTICE TO ACT NOW.")
    assert content["uppercase_ratio"] > 0.50
    assert content["content_risk_score"] >= 15

# TEST 20: Multiple Exclamation Marks
def test_20_multiple_exclamation_marks():
    """Scenario 20: Excessive punctuation signaling emotional coercion."""
    content = analyze_email_content("ALERT!!!", "Your account is locked!!! Immediate action required!!!")
    assert content["exclamation_count"] >= 3

# TEST 21: Rule-Score Boundary Calibration
def test_21_rule_score_boundaries():
    """Scenario 21: Verification of triage classification tier thresholds."""
    assert classify_risk_score(0) == "SAFE / LOW RISK"
    assert classify_risk_score(20) == "SAFE / LOW RISK"
    assert classify_risk_score(25) == "MODERATE RISK"
    assert classify_risk_score(45) == "SUSPICIOUS"
    assert classify_risk_score(75) == "HIGH RISK / LIKELY PHISHING"
    assert classify_risk_score(100) == "HIGH RISK / LIKELY PHISHING"

# TEST 22: Database Save Persistence
def test_22_database_save():
    """Scenario 22: SQLite saving and ID assignment without storing body."""
    fake_result = {
        "risk_score": 85,
        "classification": "HIGH RISK / LIKELY PHISHING",
        "detection_mode": "Rule-Based",
        "why_explanations": ["Raw IP detected"],
        "sender_analysis": {"extracted_domain": "test.invalid.test"},
        "url_analyses": []
    }
    rec_id = save_analysis(fake_result, sender="test@test.invalid.test", subject="Test Subject")
    assert rec_id > 0
    saved = get_analysis_by_id(rec_id)
    assert saved is not None
    assert saved["risk_score"] == 85

# TEST 23: API Input Validation Endpoint
def test_23_api_validation():
    """Scenario 23: Rejection of completely empty JSON payloads with HTTP 400."""
    client = app.test_client()
    resp = client.post("/api/analyze", json={})
    assert resp.status_code == 400
    assert resp.get_json()["status"] == "error"

# TEST 24: ML Model Prediction Inference
def test_24_ml_prediction_inference():
    """Scenario 24: Inference probability generation using trained model."""
    predictor = PhishingPredictor()
    if predictor.is_loaded:
        prob = predictor.predict_probability(
            "security@bank.invalid.test",
            "Urgent: Verify Account",
            "Click here immediately to verify your credentials.",
            "http://198.51.100.10/login",
            ""
        )
        assert prob is not None
        assert 0.0 <= prob <= 1.0

# TEST 25: Analysis History Retrieval & Filtering
def test_25_analysis_history_retrieval():
    """Scenario 25: Retrieval of persistent audit log with filters."""
    records = get_recent_analyses(limit=10)
    assert isinstance(records, list)
    assert len(records) > 0
