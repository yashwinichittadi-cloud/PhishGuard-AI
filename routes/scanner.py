"""
PhishGuard AI - Scanner & History Routes
Handles URL prediction endpoints, scan persistence, CSV export, and record management.
"""

import csv
import io
from flask import Blueprint, request, jsonify, render_template, abort, Response
from ml.predict import predict_url
from database.db import (
    insert_scan, get_scan_by_id, get_scan_history,
    delete_scan, clear_all_scans, seed_sample_scans_if_empty
)

scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.route("/scanner")
def scanner_page():
    """Renders the interactive AI URL Scanner page."""
    prefill_url = request.args.get("url", "")
    return render_template("scanner.html", prefill_url=prefill_url)


@scanner_bp.route("/history")
def history_page():
    """Renders the comprehensive scan history page."""
    seed_sample_scans_if_empty()
    return render_template("history.html")


@scanner_bp.route("/report/<scan_id>")
def report_page(scan_id):
    """Renders the detailed scan analysis report."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Scan record not found.")
    return render_template("report.html", scan=scan)


@scanner_bp.route("/api/scan", methods=["POST"])
def api_scan_url():
    """
    Main prediction endpoint.
    Accepts JSON: {"url": "..."} or Form data.
    Conducts purely local machine learning & lexical evaluation.
    Persists audit entry in SQLite.
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url", "").strip()
    else:
        raw_url = request.form.get("url", "").strip()

    if not raw_url:
        return jsonify({
            "success": False,
            "error": "Please provide a valid URL string to analyze."
        }), 400

    # Minimum length or structure sanity check
    if len(raw_url) < 3:
        return jsonify({
            "success": False,
            "error": "The submitted URL string is too short to evaluate."
        }), 400

    try:
        # Run ML & structural pipeline
        result = predict_url(raw_url)
        if not result.get("success", False):
            return jsonify(result), 400

        # Persist scan to SQLite
        scan_id = insert_scan(result)
        result["scan_id"] = scan_id

        return jsonify(result), 200

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Internal scan error: {str(exc)}"
        }), 500


@scanner_bp.route("/api/scans", methods=["GET"])
def api_get_scans():
    """Returns filtered, sorted scan records as JSON."""
    search = request.args.get("search", "").strip()
    filter_class = request.args.get("classification", "").strip()
    sort_by = request.args.get("sort", "date_desc").strip()
    limit = int(request.args.get("limit", 100))

    scans = get_scan_history(search=search, filter_class=filter_class, sort_by=sort_by, limit=limit)
    return jsonify({
        "success": True,
        "count": len(scans),
        "scans": scans
    })


@scanner_bp.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    """Deletes an individual scan record."""
    success = delete_scan(scan_id)
    if success:
        return jsonify({"success": True, "message": f"Scan #{scan_id} deleted successfully."})
    return jsonify({"success": False, "error": "Scan record not found."}), 404


@scanner_bp.route("/api/scans/clear", methods=["POST", "DELETE"])
def api_clear_scans():
    """Purges all scan records from SQLite."""
    count = clear_all_scans()
    return jsonify({
        "success": True,
        "message": f"Successfully cleared {count} audit records.",
        "cleared_count": count
    })


@scanner_bp.route("/api/export/csv", methods=["GET"])
def api_export_csv():
    """Generates and downloads a clean CSV export of the full audit log."""
    scans = get_scan_history(limit=5000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Scan UUID", "Submitted URL", "Domain",
        "Classification", "Risk Score (0-100)", "Model Name", "Timestamp"
    ])

    for s in scans:
        writer.writerow([
            s.get("id"),
            s.get("scan_uuid"),
            s.get("submitted_url"),
            s.get("domain"),
            s.get("classification"),
            s.get("risk_score"),
            s.get("model_name"),
            s.get("created_at")
        ])

    csv_data = output.getvalue()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=PhishGuard_Scan_History.csv"}
    )
