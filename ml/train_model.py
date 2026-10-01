"""
Phishing Email Detection & Awareness Dashboard
Module: Machine Learning Model Training & Evaluation
File: ml/train_model.py

Trains and evaluates defensive machine learning classifiers (Logistic Regression,
Multinomial Naive Bayes, Random Forest) on the synthetic email dataset.
Combines TF-IDF textual representations with structured cybersecurity feature vectors.
Evaluates metrics (Accuracy, Precision, Recall, F1, Confusion Matrix) and saves artifacts.
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import json
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from backend.services.feature_extractor import extract_email_features

FEATURE_COLUMNS = [
    "urgent_keyword_count", "credential_keyword_count", "financial_keyword_count",
    "threat_keyword_count", "url_count", "suspicious_url_count", "has_ip_url",
    "has_shortened_url_pattern", "sender_domain_length", "subdomain_count",
    "suspicious_attachment", "generic_greeting", "contains_password_request",
    "contains_personal_info_request", "exclamation_count", "uppercase_ratio",
    "body_length", "subject_length"
]

def train_and_evaluate(dataset_path="data/phishing_email_dataset.csv", output_dir="models"):
    print("[*] Loading synthetic dataset from:", dataset_path)
    df = pd.read_csv(dataset_path)
    df.fillna("", inplace=True)

    os.makedirs(output_dir, exist_ok=True)

    # 1. Text feature combination
    text_corpus = (df["subject"] + " " + df["body"]).tolist()
    labels = (df["label"] == "PHISHING").astype(int).values

    # 2. Extract structured indicator feature matrix
    print("[*] Extracting structured cybersecurity indicator features...")
    feature_rows = []
    for _, row in df.iterrows():
        feat = extract_email_features(
            sender=row["sender"],
            subject=row["subject"],
            body=row["body"],
            urls=row["urls"],
            attachment_name=row["attachment_name"]
        )
        feature_rows.append([feat[col] for col in FEATURE_COLUMNS])

    X_structured = np.array(feature_rows)

    # 3. Fit TF-IDF on text corpus
    print("[*] Fitting TF-IDF Vectorizer...")
    tfidf = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2))
    X_tfidf = tfidf.fit_transform(text_corpus).toarray()

    # Combine TF-IDF features with structured indicator features
    X_combined = np.hstack([X_tfidf, X_structured])
    y = labels

    # 4. Train-Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y, test_size=0.20, random_state=42, stratify=y
    )

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Naive Bayes": MultinomialNB(),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42)
    }

    results = {}
    best_model_name = ""
    best_f1 = -1.0
    best_model_obj = None

    print("\n" + "="*65)
    print("        MACHINE LEARNING MODEL EVALUATION RESULTS")
    print("="*65)

    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()  # [[TN, FP], [FN, TP]]

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": {
                "true_negative": cm[0][0],
                "false_positive": cm[0][1],
                "false_negative": cm[1][0],
                "true_positive": cm[1][1]
            }
        }

        print(f"\nModel: {name}")
        print(f"  Accuracy:  {acc*100:.2f}%")
        print(f"  Precision: {prec*100:.2f}% (Reduces false alerts)")
        print(f"  Recall:    {rec*100:.2f}% (Minimizes missed phishing)")
        print(f"  F1 Score:  {f1*100:.2f}% (Harmonic mean)")
        print(f"  Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model_obj = model

    # Save artifacts
    print(f"\n[+] Selected Best Model based on F1 Score: {best_model_name}")
    joblib.dump(best_model_obj, os.path.join(output_dir, "phishing_model.joblib"))
    joblib.dump(tfidf, os.path.join(output_dir, "tfidf_vectorizer.joblib"))
    
    with open(os.path.join(output_dir, "model_metrics.json"), "w", encoding="utf-8") as f:
        json.dump({
            "best_model": best_model_name,
            "models": results,
            "feature_columns": FEATURE_COLUMNS
        }, f, indent=4)

    print(f"[+] Serialized model and metrics to: {output_dir}/")
    return results

if __name__ == "__main__":
    train_and_evaluate()
