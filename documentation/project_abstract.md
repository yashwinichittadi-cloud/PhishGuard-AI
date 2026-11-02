# PhishGuard AI - Academic Project Abstract & Synopsis

**Academic Program:** Bachelor of Technology (B.Tech) in Artificial Intelligence and Data Science  
**Project Title:** PhishGuard AI: Intelligent Phishing Detection & Cybersecurity Analysis Platform  
**Domain:** Artificial Intelligence, Machine Learning, Cybersecurity & Threat Intelligence  
**Academic Year:** 2025 – 2026  

---

## Abstract

Phishing remains the single most prolific entry vector in contemporary cybercrime, responsible for over 85% of initial organizational credential breaches globally. Conventional perimeter defenses depend almost entirely on static domain reputation feeds and centralized blacklists. While effective against legacy infrastructure, static blacklists suffer from a critical temporal latency deficit—often requiring 4 to 24 hours to index newly registered malicious domains, whereas the operational lifespan of modern phishing campaigns averages under 4.5 hours. Furthermore, active web crawlers inadvertently introduce catastrophic hazards: by requesting user-submitted URLs over live sockets, crawlers expose local evaluation environments to drive-by zero-day browser exploits and transmit DNS telemetry back to threat actors.

To eliminate both the latency gap and active socket infiltration hazards, **PhishGuard AI** proposes a zero-trust, purely local Machine Learning URL threat triage platform. The architecture executes string-level decomposition and lexical feature engineering without initiating external socket connections to submitted addresses. 

The analytical pipeline extracts a hybrid feature space comprising 16 domain-engineered numerical features (including subdomain depth, host IP indicators, brand lookalike spoofing, high-abuse top-level domains, and URL shortener detection) concatenated with 800-dimensional character-level Term Frequency-Inverse Document Frequency (TF-IDF) n-grams spanning 3 to 5 characters. 

Two competitive machine learning models—**Logistic Regression** and an ensemble **Random Forest Classifier**—were trained and evaluated on deduplicated public threat intelligence feeds (PhishTank, OpenPhish, and Tranco legitimate top domains) under an 80/20 Stratified Train/Test split. The champion model achieves high classification accuracy and F1-score on held-out test partitions.

PhishGuard AI delivers a production-grade web console featuring:
1. Multi-tier classification: **Safe / Legitimate**, **Suspicious**, and **High Risk / Potential Phishing**.
2. Calibrated continuous risk scoring scaled from **0 to 100**.
3. Deep heuristic explainability cards highlighting why specific tokens and structures contributed to the threat verdict.
4. Persistent SQLite audit logging with live search, threat filtering, and CSV export.
5. Automated generation of publication-ready vector PDF threat reports via ReportLab.

The project demonstrates how character n-gram machine learning enables reliable pre-execution threat triage while upholding non-intrusive security safety directives.
