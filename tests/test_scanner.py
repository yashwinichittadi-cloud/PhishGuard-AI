"""
PhishGuard AI - Scanner, ML Engine & API Unit Tests
"""

import os
import sys
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app
from ml.feature_extraction import (
    normalize_url, is_ip_address, extract_url_components,
    extract_numerical_features, analyze_url_comprehensive
)
from ml.predict import predict_url
from routes.reports import generate_pdf_report


class TestPhishGuardScanner(unittest.TestCase):
    """Tests URL parsing, lexical feature extraction, ML inference, and reports."""

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_normalize_url(self):
        """Verifies URL scheme prefixing and whitespace stripping."""
        self.assertEqual(normalize_url(" google.com "), "http://google.com")
        self.assertEqual(normalize_url("https://secure.bank.com"), "https://secure.bank.com")
        self.assertEqual(normalize_url(""), "")

    def test_ip_address_detection(self):
        """Verifies detection of raw IPv4/IPv6 hosts vs standard domains."""
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("10.0.0.1:8080"))
        self.assertFalse(is_ip_address("www.google.com"))
        self.assertFalse(is_ip_address("paypal-verification.com"))

    def test_feature_extraction_numerical(self):
        """Verifies 16 numerical features are correctly calculated."""
        url = "http://paypal-verify-alert.com/signin/index.php"
        feats = extract_numerical_features(url)
        self.assertIn("url_len", feats)
        self.assertIn("domain_len", feats)
        self.assertIn("dot_count", feats)
        self.assertIn("hyphen_count", feats)
        self.assertIn("is_ip", feats)
        self.assertIn("is_https", feats)
        self.assertEqual(feats["is_https"], 0)
        self.assertGreater(feats["hyphen_count"], 0)

    def test_brand_spoofing_detection(self):
        """Verifies detection when brand appears in subdomain/path but not registered domain."""
        spoofed_url = "http://paypal.com.account-update.xyz/login.php"
        feats = extract_numerical_features(spoofed_url)
        self.assertEqual(feats["brand_spoofed"], 1)

        legit_url = "https://www.paypal.com/signin"
        legit_feats = extract_numerical_features(legit_url)
        self.assertEqual(legit_feats["brand_spoofed"], 0)

    def test_predict_empty_url(self):
        """Ensures system safely rejects empty URL strings."""
        res = predict_url("")
        self.assertFalse(res.get("success", False))

    def test_predict_benign_url(self):
        """Tests that a standard benign URL receives Safe classification."""
        res = predict_url("https://www.google.com")
        self.assertTrue(res["success"])
        self.assertIn(res["classification"], ["Safe / Legitimate", "Suspicious"])
        self.assertLess(res["risk_score"], 40.0)

    def test_predict_phishing_url(self):
        """Tests that a known deceptive URL receives High Risk classification."""
        phish_url = "http://paypal-verification-center-update.com/signin/auth.php"
        res = predict_url(phish_url)
        self.assertTrue(res["success"])
        self.assertEqual(res["classification"], "High Risk / Potential Phishing")
        self.assertGreaterEqual(res["risk_score"], 70.0)

    def test_api_scan_endpoint_success(self):
        """Tests JSON API scan endpoint."""
        response = self.client.post("/api/scan", json={"url": "https://www.wikipedia.org"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertIn("risk_score", data)
        self.assertIn("scan_id", data)

    def test_api_scan_endpoint_empty(self):
        """Tests JSON API returns 400 on empty input."""
        response = self.client.post("/api/scan", json={"url": " "})
        self.assertEqual(response.status_code, 400)

    def test_pdf_report_generation(self):
        """Verifies PDF generator produces valid binary PDF data."""
        mock_scan = {
            "id": 99,
            "scan_uuid": "TEST99",
            "submitted_url": "http://test-phish.xyz/login",
            "domain": "test-phish.xyz",
            "classification": "High Risk / Potential Phishing",
            "classification_slug": "danger",
            "risk_score": 95.0,
            "model_name": "Random Forest Classifier",
            "model_mode": "ML Pipeline",
            "created_at": "2026-10-31 12:00:00",
            "feature_analysis": {"url_len": 32, "is_ip": 0, "is_https": 0},
            "findings": [{"feature": "Suspicious TLD", "weight": 20, "description": "High-risk domain."}],
            "recommendations": ["Do not provide credentials."]
        }
        pdf_stream = generate_pdf_report(mock_scan)
        content = pdf_stream.getvalue()
        self.assertTrue(content.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
