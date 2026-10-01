"""
Phishing Email Detection & Awareness Dashboard
Module: Sender Analysis Engine
File: backend/services/sender_analyzer.py

Performs defensive, static analysis of email sender information, including RFC email format,
domain entropy, lookalike/typosquatting simulation, subdomain depth, and display name mismatch.
"""

import re

# Well-known brands often targeted for brand impersonation
POPULAR_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", 
    "netflix", "chase", "wellsfargo", "bankofamerica", "dhl", "fedex"
]

# Character substitutions commonly observed in typosquatting / visual homoglyphs
TYPOSQUAT_PATTERNS = {
    r"paypa[l1i]": "paypal",
    r"micr[o0]s[o0]ft": "microsoft",
    r"g[o0]{2}gle": "google",
    r"app[l1]e": "apple",
    r"amaz[o0]n": "amazon",
    r"netf[l1]ix": "netflix",
}

def analyze_sender(sender_input: str, display_name: str = "") -> dict:
    """
    Analyzes sender email syntax, domain structure, display name alignment,
    and potential brand spoofing indicators.

    Returns:
        dict: {
            "sender_risk_score": int (0-100),
            "sender_findings": list[str],
            "extracted_domain": str,
            "display_name_mismatch": bool,
            "subdomain_count": int,
            "domain_length": int
        }
    """
    findings = []
    risk_score = 0

    if not sender_input or not isinstance(sender_input, str):
        return {
            "sender_risk_score": 30,
            "sender_findings": ["No sender email address provided for validation."],
            "extracted_domain": "",
            "display_name_mismatch": False,
            "subdomain_count": 0,
            "domain_length": 0
        }

    # Extract display name and email if formatted like "PayPal Support <service@domain.com>"
    cleaned_input = sender_input.strip()
    match_bracket = re.search(r"^(.*?)\s*<([^>]+)>$", cleaned_input)
    if match_bracket:
        if not display_name:
            display_name = match_bracket.group(1).strip().strip('"\'')
        email_address = match_bracket.group(2).strip()
    else:
        email_address = cleaned_input

    # RFC 5322 basic email format validation
    email_regex = r"^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$"
    match = re.match(email_regex, email_address)

    if not match:
        findings.append("Invalid or malformed sender email address format.")
        risk_score += 40
        return {
            "sender_risk_score": min(risk_score, 100),
            "sender_findings": findings,
            "extracted_domain": "",
            "display_name_mismatch": False,
            "subdomain_count": 0,
            "domain_length": 0
        }

    domain = match.group(1).lower()
    subdomain_parts = domain.split(".")
    subdomain_count = max(0, len(subdomain_parts) - 2)
    domain_length = len(domain)

    # 1. Check excessive subdomains
    if subdomain_count >= 3:
        findings.append(f"Excessive subdomain depth ({subdomain_count} subdomains), often used to evade domain filters.")
        risk_score += 25
    elif subdomain_count == 2:
        findings.append(f"Elevated subdomain depth detected ({subdomain_count} subdomains).")
        risk_score += 10

    # 2. Check unusual domain length
    if domain_length > 30:
        findings.append(f"Unusually long sender domain ({domain_length} characters), typical in auto-generated phishing domains.")
        risk_score += 20
    elif domain_length > 22:
        findings.append("Slightly elevated domain length.")
        risk_score += 5

    # 3. Check for excessive hyphens or numbers in domain
    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        findings.append(f"High number of hyphens in domain ({hyphen_count}), a common social-engineering deception tactic.")
        risk_score += 20
    elif hyphen_count == 2:
        findings.append("Multiple hyphens present in sender domain.")
        risk_score += 10

    digit_count = sum(c.isdigit() for c in domain)
    if digit_count >= 4:
        findings.append(f"Elevated digit count in domain ({digit_count} digits), characteristic of algorithmically generated domains.")
        risk_score += 15

    # 4. Check display name mismatch (e.g. Display says 'PayPal Support' but domain is not paypal.com)
    display_mismatch = False
    if display_name:
        display_lower = display_name.lower()
        for brand in POPULAR_BRANDS:
            if brand in display_lower and brand not in domain:
                findings.append(
                    f"Display name references '{brand.capitalize()}', but sender domain '{domain}' does not belong to that organization."
                )
                risk_score += 35
                display_mismatch = True
                break

    # 5. Check synthetic lookalike / typosquatting patterns in domain
    for pattern, original in TYPOSQUAT_PATTERNS.items():
        if re.search(pattern, domain) and original not in domain:
            findings.append(f"Domain contains potential typosquatting or lookalike permutation of '{original}'.")
            risk_score += 35
            break

    # 6. Check for high-risk phishing keywords inside the domain itself
    phish_domain_keywords = ["verify", "security-alert", "portal-auth", "secure-login", "account-check", "update-bank"]
    for kw in phish_domain_keywords:
        if kw in domain:
            findings.append(f"Sender domain includes high-risk security/account keyword ('{kw}').")
            risk_score += 25
            break

    # If domain looks normal and legitimate
    if not findings:
        findings.append(f"Sender format and domain structure appear standard ({domain}).")
        risk_score = 0

    return {
        "sender_risk_score": min(risk_score, 100),
        "sender_findings": findings,
        "extracted_domain": domain,
        "display_name_mismatch": display_mismatch,
        "subdomain_count": subdomain_count,
        "domain_length": domain_length
    }
