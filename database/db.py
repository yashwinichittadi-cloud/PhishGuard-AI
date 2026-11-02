"""
PhishGuard AI - Database Operations
Manages SQLite storage for URL scan history, analytics, and reports.
"""

import os
import sqlite3
import json
from datetime import datetime, timedelta
from config import Config

DB_PATH = Config.DATABASE_PATH


def get_db_connection():
    """Returns a SQLite connection with row factory configured."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables and indexes if they do not exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_uuid TEXT UNIQUE,
            submitted_url TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            domain TEXT,
            classification TEXT NOT NULL,
            classification_slug TEXT NOT NULL,
            risk_score REAL NOT NULL,
            model_name TEXT,
            model_mode TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            feature_analysis TEXT,
            findings TEXT,
            recommendations TEXT
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification_slug)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk_score ON scans(risk_score)")
    conn.commit()
    conn.close()


def insert_scan(scan_data: dict) -> int:
    """Inserts a new scan result into the database and returns the record ID."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    import uuid
    scan_uuid = str(uuid.uuid4())[:8].upper()

    cursor.execute("""
        INSERT INTO scans (
            scan_uuid, submitted_url, normalized_url, domain,
            classification, classification_slug, risk_score,
            model_name, model_mode, created_at,
            feature_analysis, findings, recommendations
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_uuid,
        scan_data["url"],
        scan_data.get("normalized_url", scan_data["url"]),
        scan_data.get("components", {}).get("domain", ""),
        scan_data["classification"],
        scan_data["classification_slug"],
        scan_data["risk_score"],
        scan_data.get("model_name", "PhishGuard Engine"),
        scan_data.get("model_mode", "ML Pipeline"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        json.dumps(scan_data.get("numerical_features", {})),
        json.dumps(scan_data.get("findings", [])),
        json.dumps(scan_data.get("recommendations", []))
    ))

    record_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return record_id


def get_scan_by_id(scan_id: int):
    """Retrieves a single scan record with parsed JSON metadata."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ? OR scan_uuid = ?", (scan_id, str(scan_id).upper()))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    item = dict(row)
    item["feature_analysis"] = json.loads(item["feature_analysis"] or "{}")
    item["findings"] = json.loads(item["findings"] or "[]")
    item["recommendations"] = json.loads(item["recommendations"] or "[]")
    return item


def get_scan_history(search="", filter_class="", sort_by="date_desc", limit=100):
    """Retrieves scans with search, filter, and sorting capabilities."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT id, scan_uuid, submitted_url, domain, classification, classification_slug, risk_score, model_name, created_at FROM scans WHERE 1=1"
    params = []

    if search:
        query += " AND (submitted_url LIKE ? OR domain LIKE ? OR scan_uuid LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    if filter_class:
        query += " AND classification_slug = ?"
        params.append(filter_class.lower())

    if sort_by == "date_asc":
        query += " ORDER BY created_at ASC"
    elif sort_by == "risk_desc":
        query += " ORDER BY risk_score DESC"
    elif sort_by == "risk_asc":
        query += " ORDER BY risk_score ASC"
    else:
        query += " ORDER BY created_at DESC"

    query += " LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]


def delete_scan(scan_id: int) -> bool:
    """Deletes a single scan by ID."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ? OR scan_uuid = ?", (scan_id, str(scan_id).upper()))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def clear_all_scans() -> int:
    """Deletes all scan records."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    count = cursor.rowcount
    conn.commit()
    conn.close()
    return count


def get_dashboard_statistics():
    """Computes real aggregate metrics from actual SQLite database records."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total counts
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification_slug = 'safe'")
    safe_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification_slug = 'suspicious'")
    suspicious_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification_slug = 'danger'")
    high_risk_scans = cursor.fetchone()[0]

    # Average risk score
    cursor.execute("SELECT AVG(risk_score) FROM scans")
    avg_risk_row = cursor.fetchone()[0]
    avg_risk = round(avg_risk_row, 1) if avg_risk_row is not None else 0.0

    # Risk Distribution Buckets (0-19, 20-39, 40-59, 60-79, 80-100)
    risk_buckets = {
        "0-20 (Very Low)": 0,
        "21-40 (Low)": 0,
        "41-60 (Moderate)": 0,
        "61-80 (Elevated)": 0,
        "81-100 (Severe)": 0
    }
    cursor.execute("""
        SELECT 
            SUM(CASE WHEN risk_score <= 20 THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_score > 20 AND risk_score <= 40 THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_score > 40 AND risk_score <= 60 THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_score > 60 AND risk_score <= 80 THEN 1 ELSE 0 END),
            SUM(CASE WHEN risk_score > 80 THEN 1 ELSE 0 END)
        FROM scans
    """)
    b_row = cursor.fetchone()
    if b_row and total_scans > 0:
        risk_buckets["0-20 (Very Low)"] = b_row[0] or 0
        risk_buckets["21-40 (Low)"] = b_row[1] or 0
        risk_buckets["41-60 (Moderate)"] = b_row[2] or 0
        risk_buckets["61-80 (Elevated)"] = b_row[3] or 0
        risk_buckets["81-100 (Severe)"] = b_row[4] or 0

    # Daily Activity for past 7 days
    today = datetime.now().date()
    daily_labels = []
    daily_counts = []
    for i in range(6, -1, -1):
        day_date = today - timedelta(days=i)
        date_str = day_date.strftime("%Y-%m-%d")
        daily_labels.append(day_date.strftime("%b %d"))
        cursor.execute("SELECT COUNT(*) FROM scans WHERE DATE(created_at) = ?", (date_str,))
        count = cursor.fetchone()[0]
        daily_counts.append(count)

    # Recent scans (latest 5)
    cursor.execute("""
        SELECT id, scan_uuid, submitted_url, domain, classification, classification_slug, risk_score, created_at
        FROM scans ORDER BY created_at DESC LIMIT 6
    """)
    recent_scans = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return {
        "total_scans": total_scans,
        "safe_scans": safe_scans,
        "suspicious_scans": suspicious_scans,
        "high_risk_scans": high_risk_scans,
        "avg_risk": avg_risk,
        "classification_chart": {
            "labels": ["Safe / Legitimate", "Suspicious", "High Risk / Phishing"],
            "data": [safe_scans, suspicious_scans, high_risk_scans],
            "colors": ["#10b981", "#f59e0b", "#ef4444"]
        },
        "risk_distribution_chart": {
            "labels": list(risk_buckets.keys()),
            "data": list(risk_buckets.values())
        },
        "daily_activity_chart": {
            "labels": daily_labels,
            "data": daily_counts
        },
        "recent_scans": recent_scans
    }


def seed_sample_scans_if_empty():
    """Seeds a realistic initial audit log if the database is freshly initialized."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scans")
    count = cursor.fetchone()[0]
    conn.close()

    if count == 0:
        samples = [
            ("https://www.google.com", "Safe / Legitimate", "safe", 5.0, "google.com"),
            ("http://paypal-verification-center-update.com/signin/auth.php", "High Risk / Potential Phishing", "danger", 92.5, "paypal-verification-center-update.com"),
            ("https://github.com/torvalds/linux", "Safe / Legitimate", "safe", 2.0, "github.com"),
            ("http://192.168.1.100/secure-login/bankofamerica.html", "High Risk / Potential Phishing", "danger", 96.0, "192.168.1.100"),
            ("http://bit.ly/3x8Qz99-urgent-account-update", "Suspicious", "suspicious", 64.0, "bit.ly"),
            ("https://en.wikipedia.org/wiki/Phishing", "Safe / Legitimate", "safe", 4.0, "wikipedia.org"),
            ("http://netflix-billing-issue-resolved.xyz/confirm-payment", "High Risk / Potential Phishing", "danger", 88.0, "netflix-billing-issue-resolved.xyz"),
            ("http://tinyurl.com/bank-security-reactivate-now", "Suspicious", "suspicious", 58.5, "tinyurl.com"),
        ]
        import uuid
        now = datetime.now()
        conn = get_db_connection()
        cursor = conn.cursor()
        for idx, (url, classification, slug, risk, domain) in enumerate(samples):
            scan_time = (now - timedelta(hours=idx * 6 + 1)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO scans (
                    scan_uuid, submitted_url, normalized_url, domain,
                    classification, classification_slug, risk_score,
                    model_name, model_mode, created_at,
                    feature_analysis, findings, recommendations
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4())[:8].upper(),
                url,
                url,
                domain,
                classification,
                slug,
                risk,
                "Random Forest Classifier",
                "Trained Machine Learning Pipeline",
                scan_time,
                json.dumps({"url_len": len(url), "domain_hyphens": domain.count("-")}),
                json.dumps([{"feature": "Sample Baseline Entry", "type": slug, "description": "Academic benchmark audit entry."}]),
                json.dumps(["Standard security verification recommended."])
            ))
        conn.commit()
        conn.close()
