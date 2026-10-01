"""
Phishing Email Detection & Awareness Dashboard
Module: Machine Learning Inference Engine
File: ml/predict.py

Loads serialized model and TF-IDF pipeline to predict phishing probability
for arbitrary input emails.
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import joblib
import numpy as np
from backend.services.feature_extractor import extract_email_features

FEATURE_COLUMNS = [
    "urgent_keyword_count", "credential_keyword_count", "financial_keyword_count",
    "threat_keyword_count", "url_count", "suspicious_url_count", "has_ip_url",
    "has_shortened_url_pattern", "sender_domain_length", "subdomain_count",
    "suspicious_attachment", "generic_greeting", "contains_password_request",
    "contains_personal_info_request", "exclamation_count", "uppercase_ratio",
    "body_length", "subject_length"
]

class PhishingPredictor:
    def __init__(self, model_dir="models"):
        self.model_path = os.path.join(model_dir, "phishing_model.joblib")
        self.tfidf_path = os.path.join(model_dir, "tfidf_vectorizer.joblib")
        self.model = None
        self.tfidf = None
        self.is_loaded = False
        self._load()

    def _load(self):
        if os.path.exists(self.model_path) and os.path.exists(self.tfidf_path):
            try:
                self.model = joblib.load(self.model_path)
                self.tfidf = joblib.load(self.tfidf_path)
                self.is_loaded = True
            except Exception as e:
                print(f"[!] Warning: Could not load ML model: {e}")
                self.is_loaded = False

    def predict_probability(self, sender: str, subject: str, body: str, urls: str = "", attachment_name: str = "") -> float:
        """
        Returns estimated phishing probability between 0.0 (Legitimate) and 1.0 (Phishing).
        Returns None if model is unavailable.
        """
        if not self.is_loaded:
            return None

        try:
            # 1. TF-IDF text features
            text = f"{subject or ''} {body or ''}"
            tfidf_vec = self.tfidf.transform([text]).toarray()

            # 2. Structured indicator features
            feat = extract_email_features(sender, subject, body, urls, attachment_name)
            feat_vec = np.array([[feat[col] for col in FEATURE_COLUMNS]])

            # Combined representation
            X = np.hstack([tfidf_vec, feat_vec])

            # Predict probability of class 1 (PHISHING)
            proba = self.model.predict_proba(X)[0][1]
            return round(float(proba), 4)
        except Exception as e:
            print(f"[!] Prediction error: {e}")
            return None
