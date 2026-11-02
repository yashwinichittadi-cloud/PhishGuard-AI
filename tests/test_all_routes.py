"""
PhishGuard AI - Full End-to-End Route Verification Test Suite
Verifies all 14 web endpoints and services using the standard unittest framework.
"""

import os
import sys
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app
from database.db import seed_sample_scans_if_empty


class TestAllRoutes(unittest.TestCase):
    """Integration test suite covering all 14 web endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()
        seed_sample_scans_if_empty()

    def test_01_home_page(self):
        """Verifies GET / (Home Page) returns 200."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)

    def test_02_dashboard_page(self):
        """Verifies GET /dashboard (Dashboard Page) returns 200."""
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)

    def test_03_scanner_page(self):
        """Verifies GET /scanner (Scanner Page) returns 200."""
        res = self.client.get("/scanner")
        self.assertEqual(res.status_code, 200)

    def test_04_history_page(self):
        """Verifies GET /history (History Page) returns 200."""
        res = self.client.get("/history")
        self.assertEqual(res.status_code, 200)

    def test_05_performance_page(self):
        """Verifies GET /performance (Performance Page) returns 200."""
        res = self.client.get("/performance")
        self.assertEqual(res.status_code, 200)

    def test_06_awareness_page(self):
        """Verifies GET /awareness (Awareness Page) returns 200."""
        res = self.client.get("/awareness")
        self.assertEqual(res.status_code, 200)

    def test_07_about_page(self):
        """Verifies GET /about (About Page) returns 200."""
        res = self.client.get("/about")
        self.assertEqual(res.status_code, 200)

    def test_08_api_dashboard_stats(self):
        """Verifies GET /api/dashboard/stats returns 200 and JSON."""
        res = self.client.get("/api/dashboard/stats")
        self.assertEqual(res.status_code, 200)
        self.assertIsNotNone(res.get_json())

    def test_09_api_model_metrics(self):
        """Verifies GET /api/model/metrics returns 200 and JSON."""
        res = self.client.get("/api/model/metrics")
        self.assertEqual(res.status_code, 200)
        self.assertIsNotNone(res.get_json())

    def test_10_api_scans(self):
        """Verifies GET /api/scans returns 200 and scan list JSON."""
        res = self.client.get("/api/scans")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success", False))

    def test_11_detailed_report_page(self):
        """Verifies GET /report/1 (Detailed Report Page #1) returns 200."""
        res = self.client.get("/report/1")
        self.assertEqual(res.status_code, 200)

    def test_12_pdf_download(self):
        """Verifies GET /api/reports/download/1 (PDF Download for Scan #1) returns 200."""
        res = self.client.get("/api/reports/download/1")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "application/pdf")

    def test_13_csv_export(self):
        """Verifies GET /api/export/csv (CSV Export Endpoint) returns 200."""
        res = self.client.get("/api/export/csv")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/csv", res.mimetype)

    def test_14_live_scan_api_post(self):
        """Verifies POST /api/scan (Live Scan API POST) returns 200 and success=True."""
        res = self.client.post("/api/scan", json={"url": "https://www.google.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success", False))


if __name__ == "__main__":
    unittest.main()
