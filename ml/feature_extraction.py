"""
PhishGuard AI - Feature Extraction Engine
Performs purely local, non-intrusive lexical and structural analysis of URLs.
Zero network requests are initiated.
"""

import re
from urllib.parse import urlparse, unquote

# List of known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "tiny.cc", "cutt.ly"
}

# High-risk / abuse-prone TLDs frequently encountered in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "site", "gq", "cf", "tk", "ml",
    "ga", "icu", "pw", "cc", "club", "vip", "bid", "date", "win", "stream"
}

# High-profile brand names frequently targeted in credential harvesting
TARGET_BRANDS = [
    "paypal", "apple", "netflix", "chase", "wellsfargo", "bankofamerica",
    "citigroup", "citi", "amazon", "google", "microsoft", "outlook",
    "office365", "facebook", "instagram", "twitter", "whatsapp", "telegram",
    "binance", "coinbase", "metamask", "steam", "discord", "spotify",
    "dhl", "fedex", "usps", "ups", "irs", "walmart", "target", "ebay"
]

# Sensitive / Urgency keywords often used in deceptive phishing paths/parameters
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "billing", "confirm", "confirmation",
    "password", "credential", "suspend", "suspended", "restore", "wallet",
    "dispute", "refund", "re-activate", "bonus", "free", "gift", "prize",
    "urgent", "alert", "checkpoint", "token", "auth", "authorize"
]

IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

IPV6_PATTERN = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")


def normalize_url(raw_url: str) -> str:
    """Standardizes input URL without altering original semantics."""
    url = raw_url.strip()
    if not url:
        return ""
    # If no scheme provided, prepend http:// for parsing purposes
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def is_ip_address(netloc: str) -> bool:
    """Detects whether netloc is an IP address rather than a domain name."""
    host = netloc.split(":")[0].strip("[]")
    if IPV4_PATTERN.match(host):
        return True
    if ":" in host and IPV6_PATTERN.match(host):
        return True
    return False


def extract_url_components(raw_url: str):
    """
    Parses URL string safely using standard library urllib.parse.
    """
    normalized = normalize_url(raw_url)
    try:
        parsed = urlparse(normalized)
    except Exception:
        # Fallback if invalid format
        return {
            "normalized_url": raw_url,
            "scheme": "",
            "netloc": "",
            "path": "",
            "query": "",
            "fragment": "",
            "domain": "",
            "subdomains": [],
            "tld": "",
            "port": None,
        }

    netloc = parsed.netloc.lower()
    port = parsed.port
    host = netloc.split(":")[0]

    domain_parts = host.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    
    # Simple registered domain extraction
    if len(domain_parts) >= 2:
        # check multi-part TLD like .co.uk, .org.cn
        if len(domain_parts) >= 3 and domain_parts[-2] in ["co", "com", "org", "gov", "edu", "net"]:
            registered_domain = ".".join(domain_parts[-3:])
            subdomain_parts = domain_parts[:-3]
        else:
            registered_domain = ".".join(domain_parts[-2:])
            subdomain_parts = domain_parts[:-2]
    else:
        registered_domain = host
        subdomain_parts = []

    return {
        "normalized_url": normalized,
        "scheme": parsed.scheme.lower(),
        "netloc": netloc,
        "host": host,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "domain": registered_domain,
        "subdomain_parts": subdomain_parts,
        "subdomain_count": len(subdomain_parts),
        "tld": tld,
        "port": port,
    }


def extract_numerical_features(raw_url: str) -> dict:
    """
    Extracts 16 quantitative features used as inputs to Scikit-Learn models.
    """
    comp = extract_url_components(raw_url)
    url = comp["normalized_url"]
    host = comp["host"]
    path = comp["path"]
    query = comp["query"]

    # 1. URL Length
    url_len = len(url)

    # 2. Domain / Host Length
    domain_len = len(host)

    # 3. Path Length
    path_len = len(path)

    # 4. Number of dots
    dot_count = url.count(".")

    # 5. Number of hyphens
    hyphen_count = url.count("-")

    # 6. Hyphens in domain specifically
    domain_hyphens = host.count("-")

    # 7. Special characters count (@, ?, =, _, &, %, ~, +, $, !)
    special_chars = sum(url.count(c) for c in ["@", "?", "=", "_", "&", "%", "~", "+", "$", "!"])

    # 8. Presence of '@' (Credential / Auth spoofing technique)
    has_at_symbol = 1 if "@" in url else 0

    # 9. Number of subdomains
    subdomain_count = comp["subdomain_count"]

    # 10. IP address indicator
    is_ip = 1 if is_ip_address(host) else 0

    # 11. HTTPS scheme presence (1 if https, 0 otherwise)
    is_https = 1 if comp["scheme"] == "https" else 0

    # 12. URL Shortener indicator
    is_shortener = 1 if host in SHORTENER_DOMAINS else 0

    # 13. Suspicious / risky TLD indicator
    is_suspicious_tld = 1 if comp["tld"] in SUSPICIOUS_TLDS else 0

    # 14. Count of suspicious urgency/credential keywords in URL
    url_lower = url.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # 15. Targeted brand spoofing (Brand name in subdomain or path, but NOT in main registered domain)
    registered_domain = comp["domain"].lower()
    brand_spoofed = 0
    for brand in TARGET_BRANDS:
        if brand in url_lower and brand not in registered_domain:
            brand_spoofed = 1
            break

    # 16. Excessive Hex/Percent encoding
    encoded_count = url.count("%")

    return {
        "url_len": url_len,
        "domain_len": domain_len,
        "path_len": path_len,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "domain_hyphens": domain_hyphens,
        "special_chars": special_chars,
        "has_at_symbol": has_at_symbol,
        "subdomain_count": subdomain_count,
        "is_ip": is_ip,
        "is_https": is_https,
        "is_shortener": is_shortener,
        "is_suspicious_tld": is_suspicious_tld,
        "keyword_count": keyword_count,
        "brand_spoofed": brand_spoofed,
        "encoded_count": encoded_count,
    }


def analyze_url_comprehensive(raw_url: str) -> dict:
    """
    Performs full structural analysis and produces human-readable explainability
    findings, risk weights, and defensive recommendations.
    """
    comp = extract_url_components(raw_url)
    num_feats = extract_numerical_features(raw_url)
    url_lower = comp["normalized_url"].lower()

    findings = []
    total_heuristic_penalty = 0

    # 1. IP address analysis
    if num_feats["is_ip"]:
        findings.append({
            "feature": "IP Address Used as Host",
            "type": "danger",
            "icon": "bi-hdd-network",
            "weight": 35,
            "description": f"The host '{comp['host']}' is a direct IP address rather than a registered domain name. Legitimate web services rarely ask users to log in directly via bare IP addresses."
        })
        total_heuristic_penalty += 35

    # 2. At symbol analysis (@)
    if num_feats["has_at_symbol"]:
        findings.append({
            "feature": "Credential Spoofing '@' Symbol",
            "type": "danger",
            "icon": "bi-at",
            "weight": 30,
            "description": "The '@' character instructs browsers to ignore preceding text as basic-auth credentials, disguising the true destination host."
        })
        total_heuristic_penalty += 30

    # 3. Brand in subdomain / path spoofing
    if num_feats["brand_spoofed"]:
        findings.append({
            "feature": "Targeted Brand Spoofing Detected",
            "type": "danger",
            "icon": "bi-shield-exclamation",
            "weight": 30,
            "description": f"The URL mentions a known brand name (e.g. PayPal, Apple, Google, Bank) in subdomains or path, but the actual registered domain is '{comp['domain']}'."
        })
        total_heuristic_penalty += 30

    # 4. URL Shortener
    if num_feats["is_shortener"]:
        findings.append({
            "feature": "URL Shortener Service Detected",
            "type": "warning",
            "icon": "bi-scissors",
            "weight": 20,
            "description": f"Domain '{comp['host']}' is a URL shortening service. Shorteners conceal the real landing destination, a common tactic in SMS and email phishing."
        })
        total_heuristic_penalty += 20

    # 5. Suspicious TLD
    if num_feats["is_suspicious_tld"]:
        findings.append({
            "feature": "High-Abuse Top-Level Domain (TLD)",
            "type": "warning",
            "icon": "bi-globe-americas",
            "weight": 18,
            "description": f"The top-level domain '.{comp['tld']}' is recognized in threat intelligence reports for having elevated abuse and disposable domain registration rates."
        })
        total_heuristic_penalty += 18

    # 6. Excessive subdomains
    if num_feats["subdomain_count"] >= 3:
        findings.append({
            "feature": "Excessive Subdomain Depth",
            "type": "warning",
            "icon": "bi-diagram-3",
            "weight": 15,
            "description": f"The URL contains {num_feats['subdomain_count']} subdomain levels. Excessive subdomains are frequently used to confuse mobile users and mimic brand structures."
        })
        total_heuristic_penalty += 15

    # 7. Domain Hyphenation
    if num_feats["domain_hyphens"] >= 2:
        findings.append({
            "feature": "High Domain Hyphenation",
            "type": "warning",
            "icon": "bi-dash-circle",
            "weight": 12,
            "description": f"The domain '{comp['host']}' contains {num_feats['domain_hyphens']} hyphens. Attackers combine hyphens with legitimate brand words to bypass basic filters."
        })
        total_heuristic_penalty += 12

    # 8. Suspicious keywords in path/query
    if num_feats["keyword_count"] >= 2:
        findings.append({
            "feature": "Deceptive Security / Urgency Keywords",
            "type": "warning",
            "icon": "bi-exclamation-triangle",
            "weight": 15,
            "description": f"Found {num_feats['keyword_count']} urgency/authentication keywords (such as login, verify, banking, security, account) embedded in the URL path."
        })
        total_heuristic_penalty += 15

    # 9. URL length
    if num_feats["url_len"] > 80:
        findings.append({
            "feature": "Abnormally Long URL",
            "type": "info",
            "icon": "bi-rulers",
            "weight": 8,
            "description": f"Total URL length is {num_feats['url_len']} characters. Phishing URLs frequently inflate length with tracking tokens to push malicious domain names out of mobile viewports."
        })
        total_heuristic_penalty += 8

    # 10. Encoded characters
    if num_feats["encoded_count"] >= 3:
        findings.append({
            "feature": "Excessive Hex / Percent Encoding",
            "type": "info",
            "icon": "bi-file-earmark-code",
            "weight": 10,
            "description": f"Detected {num_feats['encoded_count']} percent-encoded characters, frequently employed to obfuscate malicious path strings from inspection."
        })
        total_heuristic_penalty += 10

    # 11. HTTPS Analysis (Clarifying HTTPS != Legitimate)
    if not num_feats["is_https"]:
        findings.append({
            "feature": "Insecure HTTP Protocol",
            "type": "warning",
            "icon": "bi-unlock",
            "weight": 10,
            "description": "The URL uses unencrypted HTTP. Data transmitted is vulnerable to eavesdropping and man-in-the-middle interception."
        })
        total_heuristic_penalty += 10
    else:
        findings.append({
            "feature": "HTTPS Encryption Present",
            "type": "safe",
            "icon": "bi-lock",
            "weight": 0,
            "description": "HTTPS connection encryption is present. Note: Over 80% of modern phishing websites also deploy free HTTPS certificates; TLS encrypts transport but does not verify website benevolence."
        })

    # Recommendations tailored to findings
    recommendations = []
    if total_heuristic_penalty >= 50 or num_feats["is_ip"] or num_feats["brand_spoofed"]:
        recommendations.append("Do NOT enter credentials, passwords, or payment cards on this site.")
        recommendations.append("Never download attachments or execute executables from this address.")
        recommendations.append("If this URL arrived via an email or SMS alert, access the organization's official app or type their known official web address manually.")
        recommendations.append("Report the URL to your cybersecurity department or antiphishing feeds (e.g. PhishTank, Google Safe Browsing).")
    elif total_heuristic_penalty >= 20:
        recommendations.append("Exercise heightened caution: verify the exact domain name matches the genuine service.")
        recommendations.append("Inspect if you were redirected from an unrequested message or shortened link.")
        recommendations.append("Look for standard organizational contact info before supplying any personal data.")
    else:
        recommendations.append("URL structural markers appear consistent with standard benign web conventions.")
        recommendations.append("Ensure multi-factor authentication (MFA) remains enabled on sensitive accounts.")
        recommendations.append("Always verify the address bar before entering confidential credentials.")

    return {
        "components": comp,
        "numerical_features": num_feats,
        "findings": findings,
        "recommendations": recommendations,
        "heuristic_score": min(total_heuristic_penalty, 100)
    }
