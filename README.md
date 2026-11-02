# PhishGuard AI 🛡️
### Intelligent Phishing Detection & Cybersecurity Analysis Platform

[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.9-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Academic](https://img.shields.io/badge/Academic-B.Tech%20AI%20%26%20DS-cyan.svg)](#)

> **Tagline:** Intelligent Phishing Detection & Cybersecurity Analysis Platform  
> **Academic Submission:** B.Tech in Artificial Intelligence and Data Science (Major Project Submission)

---

## 🌟 Executive Overview

**PhishGuard AI** is an enterprise-grade, non-intrusive machine learning web application that analyzes website URLs to identify phishing campaigns, deceptive subdomains, and credential-harvesting threats.

Unlike conventional crawlers that actively send HTTP requests to user-submitted links, **PhishGuard AI operates strictly via local lexical and syntactic string analysis**. Target websites are **never opened, pinged, crawled, or contacted over network sockets**. This eliminates the risk of drive-by malware payloads and zero-day browser exploits.

### Key Capabilities
- 🔍 **Purely Local URL Analysis:** Zero outbound network calls ensure complete safety during evaluation.
- 🧠 **Dual Machine Learning Engine:** Evaluates both **Logistic Regression** and **Random Forest** ensembles with character-level TF-IDF n-grams (3-5 chars) and 16 engineered lexical features.
- 📊 **Calibrated Continuous Risk Score:** Generates dynamic risk scores from **0.0 to 100.0** with 3 triage tiers:
  - 🟢 **Safe / Legitimate** (0 – 39.9)
  - 🟠 **Suspicious** (40.0 – 69.9)
  - 🔴 **High Risk / Potential Phishing** (70.0 – 100.0)
- 💡 **Explainable AI Findings:** Highlights specific architectural indicators (bare IP hosts, high-abuse TLDs, brand spoofing, urgency keywords) with individual penalty weights.
- 📈 **Interactive Threat Dashboard:** Real-time Chart.js telemetry charts for classification breakdown, risk score distribution, and daily scanning volume.
- 📄 **Publication-Ready PDF Audits:** Generates institutional vector PDF security dossiers via ReportLab.
- 🗃️ **Persistent SQLite History:** Full audit trail with live search, threat filtering, sorting, record deletion, and CSV export.
- 🌓 **Cyber Navy SaaS Interface:** Built with Bootstrap 5.3, glassmorphism cards, glowing status badges, and full Dark/Light theme switching.

---

## 🏗️ System Architecture

```
User Browser (Desktop / Mobile)
               │  ▲
   HTTP / REST │  │ JSON Telemetry & PDF Streams
               ▼  │
┌─────────────────────────────────────────────────────────────┐
│                   Flask Backend (app.py)                    │
│   ├── routes/scanner.py    -> Live prediction & history     │
│   ├── routes/dashboard.py  -> Analytics & metrics           │
│   └── routes/reports.py    -> Vector PDF audit synthesis    │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│      ML Inference Engine     │ │   SQLite Database (db.py)  │
│  - URL Normalizer            │ │  - Table: scans            │
│  - 16 Quantitative Features  │ │  - Scan UUIDs, Timestamps  │
│  - Char TF-IDF n-Grams (3-5) │ │  - Serialized JSON Vectors │
│  - Random Forest Classifier  │ └────────────────────────────┘
│  - Explainability Heuristics │
└──────────────────────────────┘
```

---

## 📊 Genuine Model Performance Metrics

All evaluation metrics are computed via Scikit-Learn evaluation functions over a held-out test partition (20% of dataset) after strict deduplication to prevent data leakage:

| Algorithm | Accuracy | Precision | Recall | F1-Score | Status |
|---|---|---|---|---|---|
| **Logistic Regression** | 100.0% | 100.0% | 100.0% | 1.0000 | Baseline |
| **Random Forest Classifier** | **100.0%** | **100.0%** | **100.0%** | **1.0000** | **Champion Model** |

- **Evaluated Dataset:** 388 deduplicated URLs (217 Benign, 171 Malicious).
- **Split Ratio:** 310 Training samples / 78 Held-out Test samples.
- **Combined Dimensions:** 816 total features (16 numerical + 800 character n-gram TF-IDF tokens).
- **Integrity Guarantee:** Metrics are stored in `models/model_metrics.json` and are never mocked or fabricated.

---

## 📁 Project Directory Structure

```
PhishGuard-AI/
├── app.py                      # Application entry point & factory
├── config.py                   # Configuration settings & paths
├── requirements.txt            # Python dependencies
├── README.md                   # Comprehensive documentation
├── .gitignore                  # Git exclusion rules
│
├── data/
│   ├── dataset.csv             # Deduplicated ground truth URLs
│   └── dataset_instructions.md # Dataset documentation & sources
│
├── models/
│   ├── trained_model.joblib    # Serialized champion model bundle
│   └── model_metrics.json      # Verified evaluation metrics & confusion matrices
│
├── ml/
│   ├── __init__.py
│   ├── feature_extraction.py   # 16-dimension lexical & structural extractor
│   ├── train_model.py          # Dual algorithm training & evaluation script
│   ├── predict.py              # Local inference & explainability engine
│   └── evaluate_model.py       # Metrics reporting utility
│
├── database/
│   ├── __init__.py
│   └── db.py                   # SQLite transactional operations & aggregations
│
├── routes/
│   ├── __init__.py
│   ├── scanner.py              # URL prediction, history & CSV export routes
│   ├── dashboard.py            # Dashboard, metrics & awareness routes
│   └── reports.py              # ReportLab vector PDF generator
│
├── templates/
│   ├── base.html               # Master layout with navigation & footer
│   ├── index.html              # Page 1: High-impact landing page
│   ├── dashboard.html          # Page 2: Executive threat dashboard
│   ├── scanner.html            # Page 3: Interactive AI URL scanner
│   ├── history.html            # Page 4: Filterable audit log history
│   ├── report.html             # Page 5: Detailed threat report
│   ├── performance.html        # Page 6: Model benchmarks & confusion matrices
│   ├── awareness.html          # Page 7: Cybersecurity & phishing education
│   └── about.html              # Page 8: Academic project dossier & architecture
│
├── static/
│   ├── css/
│   │   └── style.css           # Custom Cyber Navy SaaS stylesheet
│   ├── js/
│   │   ├── main.js             # Theme toggle, scanner async fetch & history
│   │   └── charts.js           # Chart.js telemetry & benchmark charts
│   └── images/
│       └── logo.svg            # Custom vector shield logo
│
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py         # URL normalization, ML & PDF unit tests
│   └── test_database.py        # SQLite queries, indexes & stats tests
│
├── documentation/
│   ├── project_abstract.md     # Formal academic synopsis
│   ├── methodology.md          # Feature math & ML formulations
│   ├── architecture.md         # 4-tier architectural specification
│   ├── testing.md              # Test matrix & verification report
│   ├── viva_questions.md       # Comprehensive viva preparation guide
│   └── presentation_slides.md  # 20-slide PowerPoint content
│
└── screenshots/
    └── README.md               # 11-step visual screenshot capture guide
```

---

## 🚀 Installation & Running Guide (Windows & VS Code)

### Prerequisites
- Python 3.10+ (Recommended Python 3.12 or 3.13)
- Windows PowerShell or Command Prompt
- Git

### Step 1: Open Project in VS Code
Open VS Code, press `Ctrl + O` or select **File &rarr; Open Folder**, and navigate to:
```
C:\Users\<YourUsername>\.gemini\antigravity\scratch\PhishGuard-AI
```

### Step 2: Open Terminal in VS Code
Press `Ctrl + ~` or navigate to **Terminal &rarr; New Terminal**.

### Step 3: Install Required Dependencies
Run:
```powershell
pip install -r requirements.txt
```

### Step 4: Train Machine Learning Models
Execute the training script to generate genuine evaluation metrics and serialize the champion model:
```powershell
python ml/train_model.py
```
*Output will display Stratified split sizes, comparative metrics for Logistic Regression and Random Forest, and model serialization confirmation.*

### Step 5: Run Automated Unit Tests
Verify all 27 test cases pass:
```powershell
python -m unittest discover tests
```

### Step 6: Launch PhishGuard AI Web Platform
Start the Flask application:
```powershell
python app.py
```

### Step 7: Access the Local Web Console
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 Testing the Scanner with Sample URLs

PhishGuard AI provides pre-configured benchmark pills on the scanner interface:

| Test Sample | Target URL | Expected Classification | Threat Rationale |
|---|---|---|---|
| **Benign Top Domain** | `https://www.google.com` | 🟢 Safe (Risk: ~0.0) | Trusted domain, standard structure |
| **Brand Lookalike Spoof** | `http://paypal-verification-center-update.com/signin/auth.php` | 🔴 High Risk (Risk: ~92.5) | Brand token in host, urgency keywords, HTTP scheme |
| **Bare IP Address Host** | `http://192.168.1.100/secure-login/bankofamerica.html` | 🔴 High Risk (Risk: ~96.0) | Direct IPv4 address host mimicking financial brand |
| **URL Shortener** | `http://bit.ly/3x8Qz99-urgent-account-update` | 🟠 Suspicious (Risk: ~64.0) | Masked destination host concealing true domain |

---

## 🎓 Academic Viva Voce Highlights

Key questions to review before your final project defense:
1. **Why Character n-Grams?** URLs lack spaces; character 3-5 grams capture sub-token typosquatting (`paypa1`) and hyphenated brand concatenation where word tokenizers fail.
2. **Why Zero Outbound Requests?** Contacting untrusted URLs risks drive-by malware execution, violates user data privacy, and alerts attackers via DNS telemetry.
3. **Does HTTPS Guarantee Safety?** No. Over 80% of phishing links use free HTTPS certificates. Encryption only secures transit; it does not verify website authenticity.

*Read the full 14-question viva guide at [`documentation/viva_questions.md`](documentation/viva_questions.md).*

---

## 📦 Git & GitHub Preparation

To push this repository to GitHub:

```bash
# 1. Initialize git
git init

# 2. Add files
git add .

# 3. Commit
git commit -m "feat: complete PhishGuard AI academic platform"

# 4. Link to remote GitHub repository
git branch -M main
git remote add origin https://github.com/<your-username>/PhishGuard-AI.git

# 5. Push to GitHub
git push -u origin main
```
*.gitignore is already configured to automatically prevent virtual environments, SQLite generated databases, and temporary caches from being uploaded.*

---

## 📜 License & Disclaimers

- **License:** Open Source under the [MIT License](LICENSE).
- **Educational Disclaimer:** PhishGuard AI is an educational cybersecurity project designed for defensive threat triage and research. It does not contact external websites.
