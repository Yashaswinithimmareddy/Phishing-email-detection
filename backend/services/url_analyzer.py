"""
Phishing Email Detection & Awareness Dashboard
Module: URL Analysis Engine
File: backend/services/url_analyzer.py

Provides purely static, defensive analysis of URLs without visiting or resolving them.
Analyzes protocol safety, raw IP addressing, URL shorteners, excessive subdomains,
credential/login keywords in URL paths, and character obfuscation.
"""

import re
from urllib.parse import urlparse

KNOWN_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "shorturl.at"
]

SUSPICIOUS_URL_KEYWORDS = [
    "verify", "login", "signin", "account", "update", "banking", "secure",
    "password", "auth", "confirm", "security", "portal", "token", "claim",
    "free", "gift", "refund"
]

def extract_urls_from_text(text: str) -> list[str]:
    """
    Safely extracts all URLs from raw email body or text using regex.
    """
    if not text:
        return []
    url_pattern = r"(?:https?://|www\.)[^\s<>'\"`]+"
    raw_matches = re.findall(url_pattern, text)
    cleaned = []
    for u in raw_matches:
        u_clean = u.rstrip(".,;!?)>")
        if u_clean not in cleaned:
            cleaned.append(u_clean)
    return cleaned

def analyze_url(url_string: str) -> dict:
    """
    Performs safe static inspection of a URL string.
    Does NOT connect to, ping, or resolve the URL.

    Returns:
        dict: {
            "url": str,
            "url_risk_score": int (0-100),
            "findings": list[str],
            "scheme": str,
            "hostname": str,
            "is_ip_address": bool,
            "is_https": bool,
            "is_shortened": bool,
            "subdomain_count": int,
            "url_length": int,
            "suspicious_keywords_found": list[str]
        }
    """
    if not url_string or not isinstance(url_string, str):
        return {
            "url": "",
            "url_risk_score": 0,
            "findings": ["No URL provided."],
            "scheme": "",
            "hostname": "",
            "is_ip_address": False,
            "is_https": False,
            "is_shortened": False,
            "subdomain_count": 0,
            "url_length": 0,
            "suspicious_keywords_found": []
        }

    raw_url = url_string.strip()
    if not raw_url.startswith(("http://", "https://")):
        # Prepend http:// for parsing if scheme is missing
        parsed = urlparse("http://" + raw_url)
        scheme = "unspecified (defaults to http)"
    else:
        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_clean = f"{hostname}{path}?{query}".lower()

    findings = []
    risk_score = 0
    url_len = len(raw_url)

    # 1. Scheme Analysis: Plain HTTP vs HTTPS
    is_https = scheme == "https"
    if scheme == "http":
        findings.append("Unencrypted connection (HTTP). Modern legitimate auth portals require HTTPS encryption.")
        risk_score += 20
    elif scheme != "https":
        findings.append(f"Unusual URL scheme: {scheme}")
        risk_score += 15

    # 2. Raw IP address check (e.g. http://198.51.100.10/...)
    # IPv4 regex: 4 octets between 0 and 255
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    is_ip = bool(re.match(ip_pattern, hostname))
    if is_ip:
        findings.append(f"Raw IP address host detected ({hostname}). Legitimate organizations host websites on registered domain names, not bare IPs.")
        risk_score += 45

    # 3. Known URL Shortener detection
    is_shortened = any(short in hostname for short in KNOWN_SHORTENERS)
    if is_shortened:
        findings.append("URL shortening service detected. Shorteners obscure the true destination of the link.")
        risk_score += 25

    # 4. Excessive Subdomains
    subparts = hostname.split(".")
    subdomain_count = max(0, len(subparts) - 2) if not is_ip else 0
    if subdomain_count >= 3:
        findings.append(f"Excessive subdomains ({subdomain_count}), frequently used to simulate official domain names.")
        risk_score += 25
    elif subdomain_count == 2:
        findings.append(f"Multiple subdomains ({subdomain_count}).")
        risk_score += 10

    # 5. Suspicious keywords in URL
    keywords_found = []
    for kw in SUSPICIOUS_URL_KEYWORDS:
        if kw in full_clean:
            keywords_found.append(kw)
    if keywords_found:
        findings.append(f"Suspicious security/credential keywords in URL path ({', '.join(keywords_found[:3])}).")
        risk_score += min(len(keywords_found) * 10, 30)

    # 6. Deceptive characters / Obfuscation
    if "@" in raw_url:
        findings.append("Deceptive '@' character in URL. In HTTP syntax, text preceding '@' represents credentials, hiding the true target host.")
        risk_score += 35

    if "-" in hostname and hostname.count("-") >= 2:
        findings.append(f"Multiple hyphens in hostname ({hostname.count('-')}), indicative of fraudulent lookalike branding.")
        risk_score += 15

    # 7. URL Length
    if url_len > 75:
        findings.append(f"Elevated URL length ({url_len} chars), typical of evasion parameters and token tracking.")
        risk_score += 10

    if not findings:
        findings.append(f"Static analysis found no common anomalous URL structures ({hostname}).")
        risk_score = 0

    return {
        "url": raw_url,
        "url_risk_score": min(risk_score, 100),
        "findings": findings,
        "scheme": scheme,
        "hostname": hostname,
        "is_ip_address": is_ip,
        "is_https": is_https,
        "is_shortened": is_shortened,
        "subdomain_count": subdomain_count,
        "url_length": url_len,
        "suspicious_keywords_found": keywords_found
    }
