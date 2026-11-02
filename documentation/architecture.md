# PhishGuard AI - System Architecture Specification

## 1. Architectural Model

PhishGuard AI follows a modular, 4-tier client-server architecture designed for high scalability, auditability, and zero outbound network exposure.

```
+------------------------------------------------------------------------+
|                          TIER 1: PRESENTATION LAYER                    |
|  - HTML5 / CSS3 / JavaScript (ES6+)                                   |
|  - Bootstrap 5.3 Cyber Navy SaaS Palette (Dark & Light Theme Toggles)  |
|  - Chart.js 4.4 Telemetry Visualizers (Donut, Bar, Line)               |
|  - Dynamic SVG / Canvas Semicircular Risk Gauge                        |
+------------------------------------------------------------------------+
                                    ▲
                                    │ (JSON REST / Multi-part PDF)
                                    ▼
+------------------------------------------------------------------------+
|                          TIER 2: APPLICATION & API LAYER               |
|  - Python 3.13 Flask Web Framework (Application Factory)               |
|  - Routes:                                                             |
|      * /api/scan           -> Real-time URL threat prediction           |
|      * /api/dashboard/stats-> Aggregate telemetry statistics           |
|      * /api/scans          -> Filtered, sorted audit records           |
|      * /api/export/csv     -> Streaming CSV threat history             |
|      * /api/reports/download/<id> -> ReportLab vector PDF engine       |
+------------------------------------------------------------------------+
                                    ▲
                                    │
                                    ▼
+------------------------------------------------------------------------+
|                          TIER 3: MACHINE LEARNING & HEURISTICS         |
|  - URL Normalizer & Component Parser (urllib.parse)                    |
|  - 16-Dimension Quantitative Lexical Feature Extractor                 |
|  - Character-level TF-IDF Vectorizer (ngram_range=(3,5), 800 features) |
|  - Scikit-learn StandardScaler & Feature Fusion Matrix                  |
|  - Serialized Champion Model (Joblib binary: Random Forest / LogReg)   |
|  - Heuristic Weight Engine & Defensive Recommendation Formulator       |
+------------------------------------------------------------------------+
                                    ▲
                                    │
                                    ▼
+------------------------------------------------------------------------+
|                          TIER 4: PERSISTENCE & DATA STORAGE            |
|  - SQLite3 Relational Database Engine (`phishguard.db`)                |
|      * Tables: `scans` (UUID, URL, Domain, Slug, Risk, Features, JSON) |
|      * Indexes: `idx_created_at`, `idx_classification`, `idx_risk`     |
|  - Storage: `models/trained_model.joblib`, `models/model_metrics.json` |
+------------------------------------------------------------------------+
```

---

## 2. Component Interaction Sequence

1. **User Request:** The user inputs a URL string on the web client or triggers a sample benchmark pill.
2. **Asynchronous Dispatch:** `main.js` issues a `POST /api/scan` request with payload `{"url": "..."}`.
3. **Validation & Extraction:** The backend verifies string length, standardizes the URI scheme, and computes the 16 numerical features alongside 800 character n-gram tokens.
4. **Ensemble Inference:** The serialized champion model computes the posterior probability of malicious intent.
5. **Heuristic Explainability Integration:** Structural anomalies (bare IP address, suspicious TLD, brand spoofing) are analyzed and mapped to descriptive explanations with severity penalties.
6. **Audit Storage:** The result is saved with a unique 8-character hex UUID into the SQLite `scans` table.
7. **Client Rendering:** The client updates the animated risk arc, classification badge, explainability list, and download links without refreshing the page.

---

## 3. Database Schema Specification

### Table: `scans`

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Unique sequence identifier |
| `scan_uuid` | TEXT | UNIQUE, NOT NULL | 8-character uppercase identifier for reporting |
| `submitted_url` | TEXT | NOT NULL | Raw URL string submitted by user |
| `normalized_url`| TEXT | NOT NULL | Sanitized URL string |
| `domain` | TEXT | INDEXED | Extracted registered domain / host |
| `classification`| TEXT | NOT NULL | Human-readable classification ('Safe', 'Suspicious', 'High Risk') |
| `classification_slug` | TEXT | INDEXED | Machine slug ('safe', 'suspicious', 'danger') |
| `risk_score` | REAL | INDEXED | Continuous risk score between 0.0 and 100.0 |
| `model_name` | TEXT | NOT NULL | Active classifier ('Random Forest Classifier', etc.) |
| `model_mode` | TEXT | NOT NULL | Mode ('Trained ML Pipeline' vs 'Demo Heuristic Engine') |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Audit creation timestamp |
| `feature_analysis`| TEXT | NOT NULL | JSON string containing 16 numerical feature values |
| `findings` | TEXT | NOT NULL | JSON array of explainability findings and weights |
| `recommendations` | TEXT | NOT NULL | JSON array of defensive guidance instructions |
