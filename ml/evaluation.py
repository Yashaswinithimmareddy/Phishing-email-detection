"""
Phishing Email Detection & Awareness Dashboard
Module: ML Model Evaluation & Confusion Matrix Reporting
File: ml/evaluation.py

Provides analytical evaluation reports, confusion matrix breakdowns,
and cybersecurity operational context (precision vs recall trade-offs).
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import json

def get_evaluation_report(metrics_path="models/model_metrics.json") -> dict:
    """
    Loads saved evaluation metrics and produces an analytical summary report.
    """
    if not os.path.exists(metrics_path):
        return {
            "status": "error",
            "message": "Model metrics file not found. Please train models first using `python ml/train_model.py`."
        }

    with open(metrics_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data

def print_evaluation_summary(metrics_path="models/model_metrics.json"):
    data = get_evaluation_report(metrics_path)
    if "models" not in data:
        print(data.get("message"))
        return

    print("=" * 80)
    print("      CYBERSECURITY DEFENSE - MODEL EVALUATION BENCHMARK")
    print("=" * 80)
    print(f"Top Performing Model: {data.get('best_model')}\n")
    print(f"{'Model Name':<24} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 75)

    for name, metrics in data["models"].items():
        print(
            f"{name:<24} | "
            f"{metrics['accuracy']*100:>8.2f}% | "
            f"{metrics['precision']*100:>8.2f}% | "
            f"{metrics['recall']*100:>8.2f}% | "
            f"{metrics['f1_score']*100:>8.2f}%"
        )

    print("\n" + "=" * 80)
    print("                 CONFUSION MATRIX EXPLANATIONS")
    print("=" * 80)
    for name, metrics in data["models"].items():
        cm = metrics["confusion_matrix"]
        print(f"\nModel: {name}")
        print(f"  [+] True Negatives  (Legitimate correctly marked Safe):     {cm['true_negative']}")
        print(f"  [!] False Positives (Legitimate incorrectly flagged Phish): {cm['false_positive']} (Alert fatigue risk)")
        print(f"  [!] False Negatives (Phishing incorrectly marked Safe):    {cm['false_negative']} (Breach hazard risk)")
        print(f"  [+] True Positives  (Phishing correctly detected):          {cm['true_positive']}")

    print("\n" + "=" * 80)
    print("         SOC METRICS CONTEXT: PRECISION VS RECALL")
    print("=" * 80)
    print("""
- PRECISION (Minimizing False Positives):
  High precision guarantees that when an email is quarantined or flagged as Phishing,
  it is genuinely dangerous. This protects organizational productivity and stops SOC
  analysts from suffering alert fatigue.

- RECALL (Minimizing False Negatives):
  High recall is the primary defensive safety net. Even a single false negative
  (a missed phishing email) can allow an adversary into the perimeter, leading to
  credential harvesting, ransomware execution, or data exfiltration.

- F1 SCORE (Harmonic Mean):
  Provides a balanced evaluation metric ensuring the detection pipeline neither
  misses real attacks nor overwhelms analysts with false alarms.
""")

if __name__ == "__main__":
    print_evaluation_summary()
