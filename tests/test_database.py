"""
PhishGuard AI - SQLite Database Operations Unit Tests
"""

import os
import sys
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db import (
    init_db, insert_scan, get_scan_by_id, get_scan_history,
    delete_scan, clear_all_scans, get_dashboard_statistics
)


class TestPhishGuardDatabase(unittest.TestCase):
    """Verifies SQLite persistence, queries, updates, and telemetry."""

    def setUp(self):
        init_db()

    def test_insert_and_retrieve_scan(self):
        """Tests insertion and exact retrieval of a scan record."""
        payload = {
            "url": "http://test-database-record.com/auth",
            "normalized_url": "http://test-database-record.com/auth",
            "classification": "Suspicious",
            "classification_slug": "suspicious",
            "risk_score": 62.5,
            "model_name": "Random Forest",
            "model_mode": "ML Pipeline",
            "components": {"domain": "test-database-record.com"},
            "numerical_features": {"url_len": 40, "dot_count": 2},
            "findings": [{"feature": "Test Finding", "description": "Desc"}],
            "recommendations": ["Exercise caution"]
        }
        scan_id = insert_scan(payload)
        self.assertIsInstance(scan_id, int)

        record = get_scan_by_id(scan_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["submitted_url"], payload["url"])
        self.assertEqual(record["risk_score"], 62.5)
        self.assertEqual(record["classification_slug"], "suspicious")
        self.assertEqual(record["feature_analysis"]["url_len"], 40)

        # Clean up
        delete_scan(scan_id)

    def test_search_and_filter_history(self):
        """Tests querying history with keyword search and classification filter."""
        payload = {
            "url": "https://unique-search-target-bank.org/login",
            "classification": "Safe / Legitimate",
            "classification_slug": "safe",
            "risk_score": 10.0,
            "components": {"domain": "unique-search-target-bank.org"}
        }
        scan_id = insert_scan(payload)

        # Search by keyword
        results = get_scan_history(search="unique-search-target")
        self.assertTrue(len(results) >= 1)
        self.assertTrue(any(r["id"] == scan_id for r in results))

        # Filter by classification
        safe_results = get_scan_history(filter_class="safe")
        self.assertTrue(any(r["id"] == scan_id for r in safe_results))

        # Clean up
        delete_scan(scan_id)

    def test_dashboard_statistics(self):
        """Tests that dashboard statistics return valid structure and aggregates."""
        stats = get_dashboard_statistics()
        self.assertIn("total_scans", stats)
        self.assertIn("safe_scans", stats)
        self.assertIn("suspicious_scans", stats)
        self.assertIn("high_risk_scans", stats)
        self.assertIn("classification_chart", stats)
        self.assertIn("daily_activity_chart", stats)
        self.assertEqual(len(stats["classification_chart"]["labels"]), 3)


if __name__ == "__main__":
    unittest.main()
