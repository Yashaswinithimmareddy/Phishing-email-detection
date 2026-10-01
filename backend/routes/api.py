"""
Phishing Email Detection & Awareness Dashboard
Module: REST API Blueprint
File: backend/routes/api.py

Defines defensive REST API endpoints for email triage, URL inspection,
analytical history, metrics reporting, and dashboard visualization.
"""

from flask import Blueprint, request, jsonify
from backend.services.risk_engine import calculate_phishing_score
from backend.services.url_analyzer import analyze_url
from backend.models.database import (
    save_analysis, get_recent_analyses, get_analysis_by_id,
    delete_analysis, get_dashboard_stats, seed_default_samples
)
from ml.predict import PhishingPredictor
from ml.evaluation import get_evaluation_report

api_bp = Blueprint("api", __name__, url_prefix="/api")
predictor = PhishingPredictor()

@api_bp.route("/analyze", methods=["POST"])
def analyze_email_endpoint():
    """
    Main email analysis endpoint.
    Accepts sender, subject, body, urls, attachment_name, display_name, and enable_ml flag.
    """
    data = request.get_json(silent=True) or {}
    
    sender = data.get("sender", "")
    subject = data.get("subject", "")
    body = data.get("body", "")
    urls = data.get("urls", "")
    attachment_name = data.get("attachment_name", "")
    display_name = data.get("display_name", "")
    enable_ml = data.get("enable_ml", True)

    # Basic payload validation
    if not sender and not subject and not body and not urls and not attachment_name:
        return jsonify({
            "status": "error",
            "message": "Input validation failed: Please provide at least sender, subject, body, or URL to analyze."
        }), 400

    # ML Inference
    ml_prob = None
    if enable_ml and predictor.is_loaded:
        ml_prob = predictor.predict_probability(
            sender=sender,
            subject=subject,
            body=body,
            urls=urls,
            attachment_name=attachment_name
        )

    # Calculate full risk score
    result = calculate_phishing_score(
        sender=sender,
        subject=subject,
        body=body,
        urls=urls,
        attachment_name=attachment_name,
        display_name=display_name,
        ml_probability=ml_prob
    )

    # Persist analysis metadata into database
    analysis_id = save_analysis(result, sender=sender, subject=subject)
    result["analysis_id"] = analysis_id

    return jsonify({
        "status": "success",
        "data": result
    }), 200

@api_bp.route("/analyze/url", methods=["POST"])
def analyze_url_endpoint():
    """
    Dedicated endpoint for standalone static URL security inspection.
    """
    data = request.get_json(silent=True) or {}
    url_target = data.get("url", "").strip()

    if not url_target:
        return jsonify({
            "status": "error",
            "message": "Please provide a valid URL string to analyze."
        }), 400

    analysis = analyze_url(url_target)
    return jsonify({
        "status": "success",
        "data": analysis
    }), 200

@api_bp.route("/analyses", methods=["GET"])
def get_analyses_history():
    """
    Retrieves stored analysis records with optional filtering and search.
    """
    limit = request.args.get("limit", 50, type=int)
    filter_class = request.args.get("filter", "ALL")
    search_query = request.args.get("search", None)

    records = get_recent_analyses(limit=limit, filter_class=filter_class, search=search_query)
    return jsonify({
        "status": "success",
        "count": len(records),
        "data": records
    }), 200

@api_bp.route("/analyses/<int:analysis_id>", methods=["GET"])
def get_analysis_detail(analysis_id):
    """
    Returns granular forensic findings for an individual analysis record.
    """
    record = get_analysis_by_id(analysis_id)
    if not record:
        return jsonify({
            "status": "error",
            "message": f"Analysis record #{analysis_id} not found."
        }), 404

    return jsonify({
        "status": "success",
        "data": record
    }), 200

@api_bp.route("/analyses/<int:analysis_id>", methods=["DELETE"])
def delete_analysis_endpoint(analysis_id):
    """
    Removes an analysis record from history.
    """
    success = delete_analysis(analysis_id)
    if not success:
        return jsonify({
            "status": "error",
            "message": f"Analysis record #{analysis_id} could not be deleted."
        }), 404

    return jsonify({
        "status": "success",
        "message": f"Analysis record #{analysis_id} successfully deleted."
    }), 200

@api_bp.route("/dashboard/stats", methods=["GET"])
def dashboard_stats_endpoint():
    """
    Returns aggregated metrics for top cards and charts.
    """
    stats = get_dashboard_stats()
    return jsonify({
        "status": "success",
        "data": stats
    }), 200

@api_bp.route("/dashboard/indicators", methods=["GET"])
def dashboard_indicators_endpoint():
    """
    Returns indicators and MITRE ATT&CK reference catalog.
    """
    return jsonify({
        "status": "success",
        "mitre_framework": [
            {"id": "T1566", "name": "Phishing", "description": "Adversaries send messages to gain access or harvest credentials."},
            {"id": "T1566.001", "name": "Spearphishing Attachment", "description": "Emails containing weaponized files/scripts."},
            {"id": "T1566.002", "name": "Spearphishing Link", "description": "Emails directing victims to credential harvesting sites or drive-by exploits."},
            {"id": "T1583.001", "name": "Domains / Typosquatting", "description": "Domains visually imitating legitimate corporate identities."},
            {"id": "T1204.002", "name": "User Execution: Malicious File", "description": "Tricking user into executing malicious script or double extension."}
        ]
    }), 200

@api_bp.route("/model/metrics", methods=["GET"])
def model_metrics_endpoint():
    """
    Returns benchmark metrics for trained models.
    """
    report = get_evaluation_report()
    return jsonify({
        "status": "success",
        "data": report
    }), 200

@api_bp.route("/seed-samples", methods=["POST"])
def seed_samples_endpoint():
    seed_default_samples()
    return jsonify({
        "status": "success",
        "message": "Sample triage history records verified/seeded."
    }), 200
