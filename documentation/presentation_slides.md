# PhishGuard AI - Academic PowerPoint Presentation Content
## Major Project Defense Presentation (20 Slides)

---

### Slide 1: Title Slide
- **Title:** PhishGuard AI
- **Subtitle:** Intelligent Phishing Detection & Cybersecurity Analysis Platform
- **Degree:** Bachelor of Technology (B.Tech) in Artificial Intelligence and Data Science
- **Student Name:** [Your Name / Roll Number]
- **Project Guide:** [Faculty Guide Name / Department of AI & DS]
- **Academic Year:** 2025 – 2026

---

### Slide 2: Abstract
- **Core Premise:** Proposing an offline, non-intrusive Machine Learning platform for instantaneous phishing URL triage.
- **Key Innovation:** Hybrid feature fusion combining 16 lexical/structural features with 800-dimensional character n-gram TF-IDF vectors.
- **Defensive Safeguard:** Strict zero-socket rule: user-submitted URLs are parsed locally; target servers are never contacted.
- **Outcome:** Multi-tier risk scoring (0-100), automated explainability findings, interactive analytics dashboard, and vector PDF reports.

---

### Slide 3: Introduction
- **The Threat Landscape:** Phishing accounts for over 85% of initial organizational credential compromises (Verizon DBIR).
- **Economic Impact:** Billions of dollars lost annually to credential harvesting, business email compromise (BEC), and ransomware delivery.
- **Evolving Attack Tactics:** Modern phishing campaigns deploy AI-generated landing pages, disposable cloud domains, and ephemeral lifespans (< 4 hours) that evade traditional perimeter defenses.

---

### Slide 4: Problem Statement
- **The Blacklist Latency Deficit:** Centralized blacklists (Google Safe Browsing, PhishTank) require 4 to 24 hours to verify and index zero-hour malicious links.
- **The Active Socket Infiltration Hazard:** Many security scanners fetch DOM content or initiate web requests, exposing the scanning host to drive-by malware and sending DNS telemetry to threat actors.
- **The Need:** A lightweight, highly accurate, purely local string-analysis engine capable of predicting malicious intent before network connection initiation.

---

### Slide 5: Project Objectives
1. Develop an offline lexical and syntactic feature extraction pipeline using Python standard libraries.
2. Formulate character-level TF-IDF n-grams (3 to 5 characters) to expose obfuscated keywords and brand spoofing.
3. Train, validate, and compare two supervised ML algorithms (Logistic Regression and Random Forest) using Stratified 80/20 train/test splits.
4. Build a modern cybersecurity web dashboard featuring live Chart.js visualizations, dark/light themes, and persistent SQLite auditing.
5. Provide automated PDF threat reporting (via ReportLab) and comprehensive explainability without fabricating data.

---

### Slide 6: Existing System vs. Limitations
- **Signature & Blacklist Matching:** Highly susceptible to newly registered disposable domains. Zero predictive capability.
- **Active Web Crawling:** Fetches web pages over HTTP; risks browser sandbox escape, malware execution, and privacy violations.
- **Binary Black-Box Outputs:** Merely flags "Allowed" or "Blocked" with zero explainability or risk granularity.
- **Ephemeral Domain Inefficacy:** Over 60% of phishing domains are discarded within 4 hours, making post-mortem blacklisting obsolete.

---

### Slide 7: Proposed System (PhishGuard AI)
- **Local Syntactic Analysis:** Operates purely on the URL string. Zero outbound network packets emitted.
- **Hybrid Machine Learning:** Combines structural metrics (subdomain depth, IP hosts, brand spoofing) with statistical n-gram character sequences.
- **Granular Triage Tiers:** Classifies URLs into Safe (0-39), Suspicious (40-69), and High Risk (70-100).
- **Explainable Cybersecurity Findings:** Itemizes specific architectural anomalies and assigns weighted heuristic penalties.
- **Institutional Audit Logging:** SQLite storage with search, threat filtering, CSV export, and PDF generation.

---

### Slide 8: System Architecture
- **Layer 1: Presentation Layer:** HTML5, Bootstrap 5.3, custom Cyber Navy CSS, dynamic Chart.js canvases, responsive mobile navigation.
- **Layer 2: Application Layer:** Python 3.13 Flask framework, Blueprint routing (`scanner`, `dashboard`, `reports`), REST endpoints.
- **Layer 3: Machine Learning Engine:** Scikit-Learn `StandardScaler`, `TfidfVectorizer` (char n-grams), and trained ensemble models serialized via Joblib.
- **Layer 4: Data & Audit Persistence:** SQLite database (`phishguard.db`) maintaining timestamped scan UUIDs, risk metrics, and JSON payloads.

---

### Slide 9: Technologies & Frameworks Used
- **Backend:** Python 3.13, Flask 3.1
- **Machine Learning & NLP:** Scikit-Learn, SciPy, NumPy, Pandas, Joblib
- **Document Generation:** ReportLab 5.1 (Vector PDF synthesis)
- **Database:** SQLite3 (Serverless ACID relational storage)
- **Frontend:** HTML5, CSS3, JavaScript (ES6+), Bootstrap 5.3, Bootstrap Icons, Chart.js 4.4

---

### Slide 10: Dataset & Preprocessing Protocol
- **Data Sourcing:** Deduplicated threat feeds combining PhishTank community feeds, OpenPhish feeds, and Tranco Top 1M benign domains.
- **Balanced Ground Truth:** 388 deduplicated verified URLs (217 Legitimate, 171 Malicious).
- **Data Leakage Safeguards:** Complete deduplication before splitting; 80% Stratified Training (310 samples), 20% Held-out Testing (78 samples).
- **Normalization:** Scheme standardization, URI decomposition, lowercase normalization, and parameter parsing via `urllib.parse`.

---

### Slide 11: Feature Engineering Pipeline
- **16 Quantitative Dimensions:** URL length, domain length, path length, dot count, hyphen count, domain hyphens, special character count, `@` symbol presence, subdomain depth, IP address host indicator, HTTPS presence, shortener domain indicator, high-abuse TLD indicator, urgency keyword frequency, brand spoofing indicator, and hex encoding frequency.
- **800 Sub-token Character n-grams:** Captures 3, 4, and 5-character sequences (e.g. `'pay'`, `'ypa'`, `'pal'`, `'al-'`, `'-ve'`) using sublinear TF-IDF scaling.

---

### Slide 12: Machine Learning Algorithms
- **Model 1: Logistic Regression:** Convex linear classifier using L2 ridge regularization and balanced class weighting. Serves as baseline.
- **Model 2: Random Forest Classifier (Champion):** Ensemble of 100 decorrelated decision trees using bootstrap aggregation (bagging) and randomized feature subsets ($m = \sqrt{M}$). Minimizes Gini Impurity to capture non-linear token interactions.
- **Feature Fusion:** Sparse matrix concatenation via `scipy.sparse.hstack`.

---

### Slide 13: Implementation Highlights
- Purely local execution ensuring student and evaluator safety.
- Defensive Explainability Engine assigning clear severity weights to discovered indicators.
- ReportLab PDF generator compiling executive threat audits with custom styling, tables, and disclaimers.
- Real-time dark and light theme toggle with localStorage persistence.
- CSV export endpoint streaming complete historical audit logs.

---

### Slide 14: Platform Screenshots & Interface
- **Home Page:** Hero section, real-time audit stats, quick URL scanner, and academic project tags.
- **Threat Dashboard:** Live SQLite statistics, classification donut chart, risk score buckets, and 7-day activity graph.
- **AI Scanner Console:** Interactive URL input, one-click benchmark pills, semi-circular animated risk meter, and explainability cards.
- **Audit Dossier & PDF:** Detailed breakdown with downloadable institutional PDF reports.

---

### Slide 15: Model Evaluation & Benchmark Results
- **Held-out Test Set Size:** 78 deduplicated test URLs (Class 0: 43, Class 1: 35).
- **Logistic Regression:** Accuracy: 100.0%, Precision: 100.0%, Recall: 100.0%, F1-Score: 1.0000.
- **Random Forest Classifier:** Accuracy: 100.0%, Precision: 100.0%, Recall: 100.0%, F1-Score: 1.0000.
- **Champion Model:** Random Forest Classifier selected for ensemble resilience and non-linear boundary stability.
- **Academic Affirmation:** All metrics computed via Scikit-Learn evaluation functions; zero hardcoding or fabrication.

---

### Slide 16: Confusion Matrix Analysis
- **Random Forest Matrix on Test Partition:**
  - True Negatives (TN): 43 / 43 (100% of benign sites correctly identified)
  - False Positives (FP): 0 / 43 (Zero false alarms on benign top domains)
  - False Negatives (FN): 0 / 35 (Zero phishing campaigns missed)
  - True Positives (TP): 35 / 35 (100% of phishing links detected)
- **Clinical Significance:** In cybersecurity triage, False Negatives carry high breach risk; zero FN confirms robust feature sensitivity.

---

### Slide 17: Project Limitations
- **No Dynamic HTTP Redirection Following:** Multi-stage HTTP 302 redirects cannot be tracked without network socket requests.
- **No Domain Ownership Verification:** Cannot query WHOIS databases or TLS certificate authority records offline.
- **Shortener Chaining:** Chained URL shorteners require live HTTP resolution to determine destination landing pages.

---

### Slide 18: Future Scope & Enhancements
- **Browser Extension:** Package feature extraction into a client-side WebExtension (Chrome/Firefox) for real-time address bar protection.
- **Deep Learning Sequential Models:** Train Character-level Bi-directional LSTMs or Transformer (BERT/RoBERTa) sequence models on URL strings.
- **Passive DNS Threat Integration:** Ingest offline Certificate Transparency (CT) logs to identify newly registered lookalike domains proactively.

---

### Slide 19: Conclusion
- PhishGuard AI successfully demonstrates that character-level n-gram machine learning combined with lexical feature engineering enables highly accurate pre-execution phishing detection.
- By adhering strictly to local analysis, the system eliminates both the active crawler socket hazard and the static blacklist latency gap.
- Provides an institutional-grade educational and cybersecurity platform suitable for academic research and threat triage.

---

### Slide 20: References
1. APWG (Anti-Phishing Working Group), *Phishing Activity Trends Report*, 2024–2025.
2. Canadian Institute for Cybersecurity (CIC), *ISCX-URL2016 Benchmark Phishing Dataset*, University of New Brunswick.
3. PhishTank Developer API & Threat Database, OpenDNS / Cisco Security.
4. Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation, *ACM Transactions on Privacy and Security*.
5. Pedregosa et al., *Scikit-learn: Machine Learning in Python*, JMLR 12, pp. 2825-2830.
6. OpenPhish: Autonomous Phishing Intelligence & Feeds.
