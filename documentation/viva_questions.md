# PhishGuard AI - Academic Viva Voce & Oral Examination Preparation Guide

**Degree:** Bachelor of Technology (B.Tech) in Artificial Intelligence & Data Science  
**Subject:** Major Project Viva / Technical Defense  

---

### Q1: Why did you choose Character-level TF-IDF rather than Word-level NLP?
**Model Answer:**  
URLs do not adhere to natural language syntax. They lack spaces and standard punctuation, instead utilizing concatenated alphanumeric strings, hex encodings, and hyphenated compound terms (e.g., `paypal-verify-account-security-alert.xyz`). Word-level tokenizers (like standard whitespace or Punkt tokenizers) treat this entire string as a single out-of-vocabulary (OOV) token. 

Character n-grams (spanning 3 to 5 characters) decompose URLs into sub-tokens (e.g., `'pay'`, `'ypa'`, `'pal'`, `'al-'`, `'-ve'`). This allows the model to detect typosquatting (such as `paypa1` or `g00gle`), brand mimicry, and obfuscated keywords regardless of how attackers concatenate or punctuate them.

---

### Q2: Why is your system strictly "local" without sending HTTP requests to the target URL?
**Model Answer:**  
This is a critical **cybersecurity safety requirement**:
1. **Drive-by Malware Defense:** Visiting an unvetted malicious URL risks exposing the evaluation server to zero-day browser exploits, malicious JavaScript payloads, and automated binary downloads.
2. **Reconnaissance Countermeasure:** When an automated crawler contacts a phishing server, it sends DNS queries and HTTP headers. Threat actors monitor access logs and can detect that their campaign was inspected, enabling them to instantly burn the domain or cloaked redirect to an innocuous site.
3. **Data Privacy & Compliance:** Organizations frequently evaluate confidential internal links or password-reset tokens; transmitting them over the public internet violates data sovereignty.

---

### Q3: How did you prevent Data Leakage during Machine Learning training?
**Model Answer:**  
Data leakage occurs when information from outside the training dataset is used to create or tune the model:
1. **Deduplication:** We explicitly removed all duplicate URL entries prior to splitting. If duplicate URLs were present, identical samples would exist in both train and test splits, artificially inflating accuracy.
2. **Stratified Splitting:** We used Scikit-Learn’s `train_test_split(..., stratify=y, random_state=42)` with an 80/20 ratio to ensure the test set perfectly reflects the natural class distribution.
3. **Strict Pipeline Isolation:** Feature scaling (`StandardScaler`) and TF-IDF vocabulary fitting were performed **only** on the training partition (`fit_transform`) and subsequently applied to the held-out test partition via `transform`.

---

### Q4: Does having an HTTPS certificate prove a website is safe?
**Model Answer:**  
**No, absolutely not.** This is one of the most dangerous misconceptions in end-user security. HTTPS (Hypertext Transfer Protocol Secure) only ensures that the communication channel between the user’s browser and the web server is encrypted (preventing local eavesdropping on public Wi-Fi). It provides **no guarantee** regarding the benevolence or authenticity of the destination server.

With free automated Certificate Authorities like Let's Encrypt and Cloudflare, threat actors easily provision valid TLS certificates for phishing sites in seconds. Over **80% of modern phishing websites actively use HTTPS**. PhishGuard AI explicitly notes this in its explainability findings and never treats HTTPS as proof of safety.

---

### Q5: Why did you evaluate both Logistic Regression and Random Forest?
**Model Answer:**  
In academic machine learning, it is vital to contrast a **linear baseline model** with a **non-linear ensemble classifier**:
- **Logistic Regression** serves as a convex, highly interpretable linear baseline optimizing log-loss with L2 regularization. It determines whether the decision boundary between phishing and benign tokens is linearly separable.
- **Random Forest** is an ensemble of 100 decorrelated decision trees using bagging (bootstrap aggregation) and random feature subsets. It captures complex non-linear feature interactions (for instance, the joint presence of a bare IP address combined with an urgency keyword in the path). Random Forest is selected as our champion model due to its resilience against overfitting in high-dimensional sparse spaces.

---

### Q6: What features do you extract, and how do they expose phishing?
**Model Answer:**  
We extract **16 quantitative structural features** alongside 800 character n-gram TF-IDF dimensions:
- **Host as Bare IP Address:** Legitimate businesses register branded domains. Bare IP hosts (e.g. `http://192.168.1.100/...`) strongly indicate rogue credential-harvesting servers.
- **Brand Spoofing:** We identify if a famous brand name (e.g., `PayPal`, `Apple`, `Chase`) is present in the subdomains or path while being absent from the registered root domain (e.g., `paypal.com.auth-service.xyz`).
- **Domain Hyphenation:** Attackers use hyphens to concatenate stolen brand names to bypass basic domain name filters.
- **High-Abuse TLDs:** Automated feeds reveal that extensions like `.xyz`, `.top`, `.pw`, `.icu`, and `.tk` have disproportionately high fraud-to-legitimacy ratios.
- **Credential '@' Symbol:** In HTTP URI syntax, text prior to `@` represents HTTP Basic Auth credentials. Attackers use `https://google.com@evil-phish.com` to deceive users into believing they are navigating to Google.

---

### Q7: What are the primary limitations of your current implementation?
**Model Answer:**  
Because PhishGuard AI is an offline, non-intrusive lexical scanner:
1. **Dynamic HTTP Redirection Cloaking:** We cannot track multi-hop server-side HTTP 302 redirects or geofenced IP cloaking without contacting the server.
2. **Shortener Unmasking:** Chained URL shorteners require recursive HTTP HEAD resolution to reveal the terminal landing page.
3. **Compromised Legitimate Websites:** If a legitimate domain (like a university web server) is compromised and hosts a phishing directory, purely domain-level lexical features may underrate the threat, necessitating greater reliance on path n-grams.

---

### Q8: What is your continuous Risk Score formula?
**Model Answer:**  
Our risk score is calibrated on a scale of **0.0 to 100.0**:
$$\text{Risk Score} = \min\left(100.0, \, \max\left(0.0, \, P(\text{phishing}) \times 100\right)\right)$$
If high-confidence deterministic indicators (such as bare IP hosts or explicit brand spoofing) are detected, a safety floor of 75.0 points is enforced. The score maps into three academic triage tiers:
- **0.0 to 39.9:** Low Risk (Safe / Legitimate) &rarr; Green
- **40.0 to 69.9:** Moderate Risk (Suspicious) &rarr; Amber Orange
- **70.0 to 100.0:** High Risk (Potential Phishing) &rarr; Crimson Red
