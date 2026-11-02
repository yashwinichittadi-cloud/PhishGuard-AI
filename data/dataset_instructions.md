# PhishGuard AI - Dataset Documentation & Sourcing Instructions

This document provides transparent, academically rigorous documentation on the datasets utilized and compatible with **PhishGuard AI**, their licensing, feature extraction methodology, and step-by-step instructions for obtaining and importing datasets.

---

## 1. Primary Public Dataset Sources

PhishGuard AI is designed to train on authenticated, labelled cyber threat intelligence datasets:

### A. PhishTank Community Feed
- **Organization**: OpenDNS / Cisco PhishTank
- **URL**: [https://phishtank.org/developer_info.php](https://phishtank.org/developer_info.php)
- **License**: PhishTank Developer Agreement (Free for educational and non-commercial research use)
- **Description**: Real-time verified community-submitted phishing URLs with timestamps and target brand verification.

### B. OpenPhish Autonomous Phishing Feed
- **Organization**: OpenPhish
- **URL**: [https://openphish.com/](https://openphish.com/)
- **License**: Free Community Feed License
- **Description**: Zero-day algorithmic feeds detecting active credential harvesters and banking trojans.

### C. Tranco / Alexa Top 1M (Benign Baseline)
- **Organization**: Tranco Research Project (INRIA / TU Delft)
- **URL**: [https://tranco-list.eu/](https://tranco-list.eu/)
- **License**: Creative Commons Attribution 4.0 International (CC-BY 4.0)
- **Description**: Hardened, manipulation-resistant ranking of the top benign domain names across the web, used as the legitimate ground truth.

### D. Mendeley / Kaggle Benchmark Datasets
- **Dataset**: *Malicious and Benign URLs for Phishing Detection*
- **Source**: Mendeley Data / Kaggle (e.g., UNB ISCX-URL2016 Benchmark)
- **License**: CC BY-NC 4.0

---

## 2. Bundled Balanced Dataset (`dataset.csv`)

For instant out-of-the-box training and reproducible academic demonstration, PhishGuard AI includes a balanced dataset with verified phishing URLs collected from public phishing feeds and benign URLs from trusted top domains.

### Structure of `data/dataset.csv`:
```csv
url,label
https://google.com,0
http://paypal-security-verification.update-account-auth.xyz/login.php,1
```
- `url`: Full or normalized URL string.
- `label`: Binary classification integer:
  - `0`: Legitimate / Benign URL.
  - `1`: Phishing / Malicious URL.

---

## 3. How to Import a Custom or Larger Dataset

If you wish to import a larger external dataset (e.g. 50,000+ URLs from Kaggle or Mendeley):

1. **Format the CSV file**:
   Ensure your CSV file contains at least two columns:
   - `url` (text containing the website address)
   - `label` (either `0`/`1`, or `legitimate`/`phishing`, or `benign`/`malicious`)

2. **Save the file**:
   Replace or place your file at `data/dataset.csv`.

3. **Run the Model Training Script**:
   ```bash
   python ml/train_model.py
   ```

4. **Verify Model Metrics**:
   The training script will automatically:
   - Perform Stratified 80/20 Train/Test Split.
   - Extract numerical lexical/structural features.
   - Fit character-level TF-IDF n-grams (3-to-5 grams).
   - Train Logistic Regression & Random Forest models.
   - Calculate real Accuracy, Precision, Recall, F1-score, and Confusion Matrix.
   - Save the best calibrated estimator to `models/trained_model.joblib`.
   - Store all verified evaluation metrics in `models/model_metrics.json`.
