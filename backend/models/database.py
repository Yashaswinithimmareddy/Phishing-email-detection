"""
Phishing Email Detection & Awareness Dashboard
Module: Database Models & History Persistence
File: backend/models/database.py

Manages SQLite storage for email security triage history, forensic indicators,
URL audit trails, and dashboard statistical aggregations.
DOES NOT STORE SENSITIVE EMAIL BODIES TO PRESERVE USER PRIVACY.
"""

import os
import sqlite3
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "phishing_history.db")

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyses (
        analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        sender_domain TEXT,
        subject TEXT,
        risk_score INTEGER,
        classification TEXT,
        detection_mode TEXT,
        indicators_summary TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS indicators (
        indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER,
        indicator_type TEXT,
        description TEXT,
        severity TEXT,
        FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS url_analyses (
        url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER,
        url_safe_representation TEXT,
        risk_score INTEGER,
        findings TEXT,
        FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()

def save_analysis(result: dict, sender: str = "", subject: str = "") -> int:
    """
    Saves an analysis record and its granular indicators into SQLite.
    Protects user confidentiality by storing forensic metadata only.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    sender_domain = result.get("sender_analysis", {}).get("extracted_domain", "")
    risk_score = result.get("risk_score", 0)
    classification = result.get("classification", "SAFE")
    detection_mode = result.get("detection_mode", "Rule-Based")
    explanations = result.get("why_explanations", [])
    indicators_summary = "; ".join(explanations[:3])

    cursor.execute("""
        INSERT INTO analyses (sender, sender_domain, subject, risk_score, classification, detection_mode, indicators_summary)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (sender[:120], sender_domain[:100], subject[:180], risk_score, classification, detection_mode, indicators_summary))
    
    analysis_id = cursor.lastrowid

    # Insert individual indicators
    for exp in explanations:
        cursor.execute("""
            INSERT INTO indicators (analysis_id, indicator_type, description, severity)
            VALUES (?, ?, ?, ?)
        """, (analysis_id, "SocialEngineering/Syntax", exp, "High" if risk_score >= 60 else "Medium"))

    # Insert URLs
    for u in result.get("url_analyses", []):
        cursor.execute("""
            INSERT INTO url_analyses (analysis_id, url_safe_representation, risk_score, findings)
            VALUES (?, ?, ?, ?)
        """, (analysis_id, u["url"][:200], u["url_risk_score"], "; ".join(u["findings"])))

    conn.commit()
    conn.close()
    return analysis_id

def get_recent_analyses(limit: int = 50, filter_class: str = None, search: str = None) -> list[dict]:
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM analyses WHERE 1=1"
    params = []

    if filter_class and filter_class.upper() != "ALL":
        query += " AND classification LIKE ?"
        params.append(f"%{filter_class}%")

    if search:
        query += " AND (subject LIKE ? OR sender LIKE ? OR sender_domain LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    query += " ORDER BY analysis_id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_analysis_by_id(analysis_id: int) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    record = dict(row)

    cursor.execute("SELECT * FROM indicators WHERE analysis_id = ?", (analysis_id,))
    record["indicators"] = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM url_analyses WHERE analysis_id = ?", (analysis_id,))
    record["urls"] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return record

def delete_analysis(analysis_id: int) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
    cursor.execute("DELETE FROM indicators WHERE analysis_id = ?", (analysis_id,))
    cursor.execute("DELETE FROM url_analyses WHERE analysis_id = ?", (analysis_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def get_dashboard_stats() -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM analyses")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM analyses WHERE classification LIKE '%HIGH RISK%' OR classification LIKE '%PHISHING%'")
    high_risk = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM analyses WHERE classification LIKE '%SUSPICIOUS%'")
    suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM analyses WHERE classification LIKE '%SAFE%' OR classification LIKE '%LOW RISK%'")
    low_risk = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM analyses")
    avg_score_raw = cursor.fetchone()[0]
    avg_score = round(avg_score_raw, 1) if avg_score_raw is not None else 0.0

    # Classification breakdown
    cursor.execute("SELECT classification, COUNT(*) as count FROM analyses GROUP BY classification")
    class_dist = {r["classification"]: r["count"] for r in cursor.fetchall()}

    # Recent score trends (last 10)
    cursor.execute("SELECT analysis_id, risk_score, created_at FROM analyses ORDER BY analysis_id DESC LIMIT 10")
    trend = [{"id": r["analysis_id"], "score": r["risk_score"], "time": r["created_at"]} for r in reversed(cursor.fetchall())]

    # Indicator occurrences
    cursor.execute("SELECT description, COUNT(*) as cnt FROM indicators GROUP BY description ORDER BY cnt DESC LIMIT 7")
    top_indicators = [{"label": r["description"][:45] + "...", "count": r["cnt"]} for r in cursor.fetchall()]

    conn.close()

    return {
        "total_analyzed": total,
        "high_risk": high_risk,
        "suspicious": suspicious,
        "low_risk": low_risk,
        "average_risk_score": avg_score,
        "classification_distribution": class_dist,
        "score_trend": trend,
        "top_indicators": top_indicators
    }

def seed_default_samples():
    """
    Populates sample triage entries if database is freshly created.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM analyses")
    if cursor.fetchone()[0] == 0:
        samples = [
            ("security-alert@account-check.invalid.test", "account-check.invalid.test", "URGENT: Verify Your Account Immediately", 88, "HIGH RISK / LIKELY PHISHING", "Hybrid (Rule-Based + ML Model)", "Credential Request: Email solicits password; Artificial Urgency; Suspicious URL"),
            ("billing-support@paypal-secure-portal.invalid.test", "paypal-secure-portal.invalid.test", "Action Required: Outstanding Invoice #INV-9902 Payment Overdue", 92, "HIGH RISK / LIKELY PHISHING", "Hybrid (Rule-Based + ML Model)", "Attachment Risk: Executable/double extension; Financial Trigger; Urgency"),
            ("hr-announcements@workplace.example.org", "workplace.example.org", "HR Policy Update: Annual Benefits Enrollment", 8, "SAFE / LOW RISK", "Hybrid (Rule-Based + ML Model)", "Standard corporate communication traits"),
            ("registrar@university.example.edu", "university.example.edu", "Quarterly Academic Schedule Announcement", 5, "SAFE / LOW RISK", "Hybrid (Rule-Based + ML Model)", "Standard campus advisory without urgency"),
            ("service@bank-verification-center.invalid.test", "bank-verification-center.invalid.test", "Suspicious Activity Warning: Debit Card Temporarily Locked", 85, "HIGH RISK / LIKELY PHISHING", "Hybrid (Rule-Based + ML Model)", "Personal info solicitation; Urgency; Intimidation / Fear"),
            ("project-lead@team.example.com", "team.example.com", "Project Sprint Planning Meeting Notes", 4, "SAFE / LOW RISK", "Rule-Based Engine", "Standard project coordination email"),
        ]
        for s in samples:
            cursor.execute("""
                INSERT INTO analyses (sender, sender_domain, subject, risk_score, classification, detection_mode, indicators_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, s)
        conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    seed_default_samples()
    print("[+] Database initialized and sample triage records seeded successfully.")
