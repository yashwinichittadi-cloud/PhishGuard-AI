# PhishGuard AI - Verification & Testing Specification

## 1. Test Strategy & Scope

PhishGuard AI employs automated unit and integration tests under the Python standard library `unittest` framework to ensure stability across URL normalization, numerical extraction, model inference, SQLite transactions, and PDF generation.

---

## 2. Test Execution

Execute the full automated test suite from the project root:

```bash
python -m unittest discover tests
```

---

## 3. Test Cases & Verification Matrix

| Test Suite | Test Case Function | Verification Target | Expected Result | Status |
|---|---|---|---|---|
| `test_scanner.py` | `test_normalize_url` | URL scheme prefixing & whitespace cleanup | Prepends `http://` if omitted; trims leading/trailing spaces | PASS |
| `test_scanner.py` | `test_ip_address_detection` | IPv4 / IPv6 host regex | Returns `True` for `192.168.1.1` and `False` for `google.com` | PASS |
| `test_scanner.py` | `test_feature_extraction_numerical` | Computation of 16 quantitative features | Dictionary contains all 16 metrics with correct data types | PASS |
| `test_scanner.py` | `test_brand_spoofing_detection` | Subdomain & path brand spoofing | Flags `paypal.com.xyz` as spoofed; clears `paypal.com` | PASS |
| `test_scanner.py` | `test_predict_empty_url` | Boundary condition on empty string | Returns `{"success": False}` without unhandled exceptions | PASS |
| `test_scanner.py` | `test_predict_benign_url` | ML classification of known benign domains | Verdict is 'Safe / Legitimate'; Risk Score < 40.0 | PASS |
| `test_scanner.py` | `test_predict_phishing_url` | ML classification of credential harvesters | Verdict is 'High Risk'; Risk Score >= 70.0 | PASS |
| `test_scanner.py` | `test_api_scan_endpoint_success` | REST API `POST /api/scan` | HTTP 200, valid JSON response with `scan_id` | PASS |
| `test_scanner.py` | `test_api_scan_endpoint_empty` | REST API empty input handling | HTTP 400 Bad Request with descriptive error message | PASS |
| `test_scanner.py` | `test_pdf_report_generation` | Vector PDF document generation via ReportLab | Stream begins with valid `%PDF` magic bytes | PASS |
| `test_database.py`| `test_insert_and_retrieve_scan` | SQLite insert & parsed JSON retrieval | Record stored and retrieved with exact field fidelity | PASS |
| `test_database.py`| `test_search_and_filter_history`| SQLite search query & classification filter | Returns matching records; filters exclude non-matches | PASS |
| `test_database.py`| `test_dashboard_statistics` | Aggregate telemetry calculations | Total, safe, suspicious, phishing counts are accurate | PASS |
| `test_all_routes.py`| `test_01_home_page` | HTTP GET `/` (Home View) | HTTP 200 OK | PASS |
| `test_all_routes.py`| `test_02_dashboard_page` | HTTP GET `/dashboard` (Executive Dashboard) | HTTP 200 OK | PASS |
| `test_all_routes.py`| `test_03_scanner_page` | HTTP GET `/scanner` (Interactive Scanner) | HTTP 200 OK | PASS |
| `test_all_routes.py`| `test_04_history_page` | HTTP GET `/history` (Audit Log History) | HTTP 200 OK | PASS |
| `test_all_routes.py`| `test_05_performance_page` | HTTP GET `/performance` (Model Performance) | HTTP 200 OK | PASS |
| `test_all_routes.py`| `test_06_awareness_page` | HTTP GET `/awareness` (Cyber Awareness) | HTTP 200 OK | PASS |
| `test_all_routes.py`| `test_07_about_page` | HTTP GET `/about` (Architecture & Dossier) | HTTP 200 OK | PASS |
| `test_all_routes.py`| `test_08_api_dashboard_stats` | HTTP GET `/api/dashboard/stats` | HTTP 200 JSON | PASS |
| `test_all_routes.py`| `test_09_api_model_metrics` | HTTP GET `/api/model/metrics` | HTTP 200 JSON | PASS |
| `test_all_routes.py`| `test_10_api_scans` | HTTP GET `/api/scans` (History JSON API) | HTTP 200 JSON (`success=True`) | PASS |
| `test_all_routes.py`| `test_11_detailed_report_page` | HTTP GET `/report/1` (Detailed Report View) | HTTP 200 OK | PASS |
| `test_all_routes.py`| `test_12_pdf_download` | HTTP GET `/api/reports/download/1` | HTTP 200 `application/pdf` | PASS |
| `test_all_routes.py`| `test_13_csv_export` | HTTP GET `/api/export/csv` | HTTP 200 `text/csv` | PASS |
| `test_all_routes.py`| `test_14_live_scan_api_post` | HTTP POST `/api/scan` with URL JSON payload | HTTP 200 JSON (`success=True`) | PASS |

---

## 4. Resilience & Error Handling Validation

1. **Missing Model Artifact Resilience:** If `models/trained_model.joblib` is absent or deleted, the application seamlessly activates **Demo Heuristic Engine**, surfacing a transparent badge without crashing.
2. **Missing Dataset Resilience:** If `data/dataset.csv` is absent, the system retains existing serialized models and directs administrators to `data/dataset_instructions.md`.
3. **Invalid URL Characters:** Characters such as non-ASCII unicode or invalid escape sequences are safely sanitized via `urllib.parse` fallback blocks.
