"""
Phishing Email Detection & Awareness Dashboard
Module: Backend Application Entry Point
File: backend/app.py

Launches Flask web application, registers API blueprints, serves security awareness dashboard,
and applies defensive HTTP headers to prevent web application vulnerabilities.
"""

import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, send_from_directory, jsonify
from backend.routes.api import api_bp
from backend.models.database import init_db, seed_default_samples

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

# Register API Blueprint
app.register_blueprint(api_bp)

# Defensive Security Headers Middleware
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Safe Content Security Policy allowing CDNs for Bootstrap, FontAwesome, Chart.js
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:;"
    )
    return response

@app.route("/")
def index():
    """Serves the primary Cyber Defense & Phishing Awareness Dashboard UI."""
    return render_template("index.html")

@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Resource not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"status": "error", "message": "Internal server error"}), 500

def create_app():
    init_db()
    seed_default_samples()
    return app

if __name__ == "__main__":
    init_db()
    seed_default_samples()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n==================================================================")
    print(f"  PHISHING EMAIL DETECTION & AWARENESS DASHBOARD ACTIVE")
    print(f"  Local URL: http://127.0.0.1:{port}")
    print(f"  Defensive Mode: Static inspection without web resolution")
    print(f"==================================================================\n")
    app.run(host="127.0.0.1", port=port, debug=True)
