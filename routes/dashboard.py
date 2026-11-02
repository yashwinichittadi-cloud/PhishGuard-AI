"""
PhishGuard AI - Dashboard, Metrics & Static Navigation Routes
Serves analytics, educational resources, model performance audits, and system architecture docs.
"""

from flask import Blueprint, render_template, jsonify
from database.db import get_dashboard_statistics, seed_sample_scans_if_empty
from ml.evaluate_model import get_evaluation_metrics

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def home():
    """Renders the high-impact landing page."""
    seed_sample_scans_if_empty()
    stats = get_dashboard_statistics()
    return render_template("index.html", stats=stats)


@dashboard_bp.route("/dashboard")
def dashboard_page():
    """Renders the executive analytics dashboard."""
    seed_sample_scans_if_empty()
    stats = get_dashboard_statistics()
    return render_template("dashboard.html", stats=stats)


@dashboard_bp.route("/performance")
def performance_page():
    """Renders the Machine Learning model evaluation and comparison page."""
    metrics = get_evaluation_metrics()
    return render_template("performance.html", metrics=metrics)


@dashboard_bp.route("/awareness")
def awareness_page():
    """Renders the comprehensive cybersecurity educational curriculum."""
    return render_template("awareness.html")


@dashboard_bp.route("/about")
def about_page():
    """Renders the academic project architecture, methodology, algorithms, and viva docs."""
    return render_template("about.html")


@dashboard_bp.route("/api/dashboard/stats")
def api_dashboard_stats():
    """Delivers live SQLite database statistics for Chart.js updates."""
    stats = get_dashboard_statistics()
    return jsonify(stats)


@dashboard_bp.route("/api/model/metrics")
def api_model_metrics():
    """Returns calculated ML metrics and confusion matrix data."""
    metrics = get_evaluation_metrics()
    return jsonify(metrics)
