"""
PhishGuard AI - Application Entry Point
Intelligent Phishing Detection & Cybersecurity Analysis Platform.
College Academic Submission & Threat Intelligence Platform.
"""

import os
import sys

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, render_template
from config import Config
from database.db import init_db, seed_sample_scans_if_empty
from routes.dashboard import dashboard_bp
from routes.scanner import scanner_bp
from routes.reports import reports_bp


def create_app(config_class=Config):
    """Application factory for PhishGuard AI."""
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(config_class)

    # Initialize Database
    with app.app_context():
        init_db()
        seed_sample_scans_if_empty()

    # Register Blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(reports_bp)

    # Custom Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("base.html", error_title="404 - Page Not Found",
                               error_msg="The requested threat intelligence resource or report does not exist."), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("base.html", error_title="500 - System Error",
                               error_msg="An unexpected error occurred during analysis. Please check application logs."), 500

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 70)
    print("🛡️  PHISHGUARD AI PLATFORM STARTED")
    print(f"    Access Local Threat Intelligence Console: http://127.0.0.1:{port}")
    print("    Purely Local URL Analysis Active (Zero outbound network calls)")
    print("=" * 70)
    app.run(host="127.0.0.1", port=port, debug=True)
