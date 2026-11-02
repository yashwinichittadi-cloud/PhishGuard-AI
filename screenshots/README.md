# PhishGuard AI - Academic Presentation Screenshot Checklist

This checklist guides you through capturing high-resolution screenshots of the running application for your final project report and PowerPoint slides.

---

## Recommended Screenshot Settings
- **Browser:** Google Chrome or Microsoft Edge
- **Resolution:** 1920 x 1080 (1080p Full HD)
- **Zoom Level:** 100% or 90%
- **Theme:** Capture key views in both Dark Mode and Light Mode for maximum visual impact.

---

## Screenshot Checklist

### 1. `01_home_hero.png` (Home Page - Hero & Quick Scanner)
- **URL:** `http://127.0.0.1:5000/`
- **Focus:** Show the hero heading, student academic badge, the quick URL search widget, benchmark test pills, and live audit telemetry numbers.

### 2. `02_home_how_it_works.png` (Home Page - Pipeline Section)
- **URL:** `http://127.0.0.1:5000/` (Scroll down)
- **Focus:** The 4-step pipeline cards (Normalization &rarr; Lexical Extraction &rarr; TF-IDF Character n-Grams &rarr; Risk & Explainability) and the Zero-Trust security directive box.

### 3. `03_dashboard_analytics.png` (Executive Threat Dashboard)
- **URL:** `http://127.0.0.1:5000/dashboard`
- **Focus:** 4 stat cards (Total, Safe, Suspicious, High Risk), the Donut Chart (Classification Distribution), the Bar Chart (Risk Score Buckets), and the Line Chart (Daily Volume).

### 4. `04_scanner_benign_result.png` (URL Scanner - Safe Result)
- **URL:** `http://127.0.0.1:5000/scanner`
- **Action:** Click the sample pill `google.com` or scan `https://www.google.com`.
- **Focus:** The green animated risk arc (< 20 score), the green "Safe / Legitimate" badge, the quantitative feature values table, and the safe explainability findings.

### 5. `05_scanner_phishing_result.png` (URL Scanner - Phishing Result)
- **URL:** `http://127.0.0.1:5000/scanner`
- **Action:** Click the sample pill `PayPal Spoof` (`http://paypal-verification-center-update.com/signin/auth.php`).
- **Focus:** The red animated risk arc (90+ score), the crimson "High Risk / Potential Phishing" badge, the brand spoofing finding card, the urgency keyword card, and actionable defense recommendations.

### 6. `06_audit_history.png` (Scan History Table)
- **URL:** `http://127.0.0.1:5000/history`
- **Focus:** The audit log table with colored threat badges, UUIDs, search bar, classification dropdown, sort filter, and the "Export CSV" and "Clear Audit Log" buttons.

### 7. `07_detailed_report.png` (Detailed Threat Report)
- **URL:** `http://127.0.0.1:5000/report/1` (or click 'Audit' on any record in History)
- **Focus:** The full-width colored classification banner, target URL overview, quantitative feature table, heuristic severity weights, and the defensive disclosure notice.

### 8. `08_pdf_report_preview.png` (Generated PDF Document)
- **Action:** Click "Download Official PDF" on any report.
- **Focus:** Open the downloaded `PhishGuard_Report_<UUID>.pdf` in a PDF viewer and take a screenshot showing the formal letterhead, colored verdict box, table formatting, and disclaimers.

### 9. `09_model_performance.png` (Model Evaluation & Metrics)
- **URL:** `http://127.0.0.1:5000/performance`
- **Focus:** The dataset split cards, the Algorithm Benchmark Comparison chart (Logistic Regression vs Random Forest), the scorecard table, and both confusion matrices.

### 10. `10_cybersecurity_awareness.png` (Cybersecurity Awareness Page)
- **URL:** `http://127.0.0.1:5000/awareness`
- **Focus:** The visual "Anatomy of a Phishing URL" breakdown box (protocol, deceptive subdomain, real domain, action path) and the common attack vectors grid.

### 11. `11_about_architecture.png` (Academic Architecture & Methodology)
- **URL:** `http://127.0.0.1:5000/about`
- **Focus:** The 4-layer system architecture diagram cards, the mathematical formulas (TF-IDF, Sigmoid, Gini Impurity), and the comparative Existing vs Proposed system matrix.
