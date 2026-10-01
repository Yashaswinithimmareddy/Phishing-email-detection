"""
Phishing Email Detection & Awareness Dashboard
Module: Attachment Analysis Engine
File: backend/services/attachment_analyzer.py

Performs safe, static metadata and filename inspection of email attachments.
Identifies weaponized formats, executable payloads, script engines, macro-enabled documents,
and deceptive double extensions (e.g. invoice.pdf.exe).
DOES NOT EXECUTE ANY ATTACHMENTS.
"""

import os

# High-risk executable & script extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", 
    ".msi", ".jar", ".hta", ".cpl", ".pif", ".wsf", ".com"
}

# Macro-enabled office formats often used for initial payload staging
MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}

# Container and disk image formats used to bypass email gateway filters
CONTAINER_EXTENSIONS = {
    ".iso", ".img", ".vhd", ".dmg"
}

# Benign common office and media extensions
SAFE_EXTENSIONS = {
    ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", 
    ".png", ".jpg", ".jpeg", ".gif"
}

def analyze_attachment(filename: str) -> dict:
    """
    Performs static filename and extension inspection.

    Returns:
        dict: {
            "filename": str,
            "attachment_risk_score": int (0-100),
            "findings": list[str],
            "is_suspicious": bool,
            "is_double_extension": bool,
            "detected_extension": str
        }
    """
    if not filename or not isinstance(filename, str) or not filename.strip():
        return {
            "filename": "",
            "attachment_risk_score": 0,
            "findings": ["No attachment included."],
            "is_suspicious": False,
            "is_double_extension": False,
            "detected_extension": ""
        }

    clean_name = filename.strip()
    findings = []
    risk_score = 0
    is_suspicious = False
    is_double_extension = False

    # Extract all dot-separated tokens
    parts = clean_name.lower().split(".")
    
    if len(parts) < 2:
        findings.append("Attachment lacks a recognized file extension.")
        risk_score += 15
        detected_ext = ""
    else:
        detected_ext = "." + parts[-1]
        
        # 1. Double extension check (e.g. invoice.pdf.exe, salary.xlsx.vbs)
        if len(parts) >= 3:
            fake_ext = "." + parts[-2]
            if fake_ext in SAFE_EXTENSIONS and detected_ext in EXECUTABLE_EXTENSIONS:
                is_double_extension = True
                is_suspicious = True
                findings.append(
                    f"CRITICAL: Deceptive double extension detected ('{fake_ext}{detected_ext}'). "
                    "Attackers exploit default OS settings where extensions are hidden to mask executables as documents."
                )
                risk_score += 85

        # 2. Executable / script payload check
        if detected_ext in EXECUTABLE_EXTENSIONS:
            is_suspicious = True
            findings.append(
                f"High-risk executable or scripting extension detected ('{detected_ext}'). "
                "Email attachments with direct execution capabilities are an extreme security hazard (MITRE T1204)."
            )
            risk_score += 65

        # 3. Macro-enabled document check
        elif detected_ext in MACRO_EXTENSIONS:
            is_suspicious = True
            findings.append(
                f"Macro-enabled document format detected ('{detected_ext}'). "
                "Embedded VBA macros are historically leveraged in weaponized phishing attachments."
            )
            risk_score += 40

        # 4. Container / Disk Image check
        elif detected_ext in CONTAINER_EXTENSIONS:
            is_suspicious = True
            findings.append(
                f"Disk image / container format detected ('{detected_ext}'). "
                "Attackers use container files to bypass email gateway MOTW (Mark of the Web) protections."
            )
            risk_score += 35

        # 5. Standard safe document
        elif detected_ext in SAFE_EXTENSIONS:
            findings.append(f"Standard document format ('{detected_ext}'). Verify integrity and origin before opening.")
            risk_score += 5
        else:
            findings.append(f"Uncommon file extension ('{detected_ext}'). Treat with caution.")
            risk_score += 15

    return {
        "filename": clean_name,
        "attachment_risk_score": min(risk_score, 100),
        "findings": findings,
        "is_suspicious": is_suspicious,
        "is_double_extension": is_double_extension,
        "detected_extension": detected_ext
    }
