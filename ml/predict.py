"""
PhishGuard AI - Prediction & Inference Engine
Combines Machine Learning model probabilities with deep structural explainability.
Purely local analysis - zero external network requests.
"""

import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import joblib
import pandas as pd
from scipy.sparse import hstack
from ml.feature_extraction import extract_numerical_features, analyze_url_comprehensive
MODEL_PATH = os.path.join(BASE_DIR, "models", "trained_model.joblib")

_MODEL_CACHE = None


def load_model():
    """Loads the serialized model artifact with lazy caching."""
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    if os.path.exists(MODEL_PATH):
        try:
            _MODEL_CACHE = joblib.load(MODEL_PATH)
            return _MODEL_CACHE
        except Exception as e:
            print(f"[!] Warning: Error loading model from {MODEL_PATH}: {e}")
            return None
    return None


def predict_url(raw_url: str) -> dict:
    """
    Performs full prediction on a given URL.
    Returns:
    - classification ('Safe / Legitimate', 'Suspicious', 'High Risk / Potential Phishing')
    - risk_score (0 - 100)
    - probability (calibrated float 0.0 - 1.0)
    - model_name
    - model_mode ('Trained ML Pipeline' vs 'Demo Heuristic Engine')
    - explanation findings
    - recommendations
    - components
    """
    url_str = str(raw_url).strip()
    if not url_str:
        return {
            "error": "URL cannot be empty.",
            "success": False
        }

    # Extract deep explainability and components
    analysis = analyze_url_comprehensive(url_str)
    num_feats = analysis["numerical_features"]
    heuristic_penalty = analysis["heuristic_score"]

    model_bundle = load_model()

    if model_bundle is not None:
        try:
            model = model_bundle["model"]
            scaler = model_bundle["scaler"]
            tfidf = model_bundle["tfidf"]
            model_name = model_bundle.get("model_name", "Trained ML Classifier")

            # Transform numerical features
            df_feat = pd.DataFrame([num_feats])
            X_num = scaler.transform(df_feat)

            # Transform TF-IDF n-grams
            X_tfidf = tfidf.transform([analysis["components"]["normalized_url"]])

            # Stack features
            X_combined = hstack([X_num, X_tfidf]).tocsr()

            # Predict probability
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X_combined)[0]
                phishing_prob = float(probs[1])
            else:
                pred = int(model.predict(X_combined)[0])
                phishing_prob = 0.9 if pred == 1 else 0.1

            # -----------------------------------------------------------------------
            # BLENDED SCORING FORMULA
            # -----------------------------------------------------------------------
            # Pure ML probability on this dataset tends to cluster near 0 or 1
            # because the training set has clean separation between obvious benign
            # (well-known HTTPS domains) and obvious phishing (keyword-stuffed HTTP
            # domains). To produce meaningful intermediate scores, we blend the ML
            # probability signal with the independently-computed structural heuristic
            # penalty score.
            #
            # Formula:
            #   ml_component  = phishing_prob × 100        (model confidence 0–100)
            #   heuristic_component = structural_penalty   (rule-based 0–100)
            #   blended_score = 0.65 × ml + 0.35 × heuristic
            #
            # This preserves ML as the dominant signal (65 %) while heuristic
            # features supply gradient when ML probabilities are extreme.
            # -----------------------------------------------------------------------
            ml_component = phishing_prob * 100.0
            heuristic_component = float(heuristic_penalty)

            blended_score = (0.65 * ml_component) + (0.35 * heuristic_component)

            # Hard floor for URLs that contain direct IP addresses or confirmed brand
            # spoofing — these are near-certain phishing indicators regardless of
            # model probability, so they must never fall below High Risk threshold.
            if num_feats["is_ip"] or num_feats["brand_spoofed"]:
                risk_score = max(blended_score, 70.0)
            else:
                risk_score = blended_score

            model_mode = f"Trained ML Pipeline ({model_name}) \u2014 Blended Score (65% ML + 35% Structural Heuristic)"
            is_demo = False

        except Exception as err:
            print(f"[!] Error during ML prediction: {err}. Falling back to Rule-Based Demo Mode.")
            risk_score = float(heuristic_penalty)
            model_mode = "Demo Heuristic Engine (ML inference exception encountered)"
            model_name = "Rule-Based Heuristic Baseline"
            is_demo = True
    else:
        # Transparently declare Demo mode when model artifact is absent
        risk_score = float(heuristic_penalty)
        model_mode = "Demo Heuristic Engine (Trained model file not found. Run 'python ml/train_model.py' to activate full ML pipeline)"
        model_name = "Structural Heuristic Classifier"
        is_demo = True

    # Clamp risk score between 0 and 100
    risk_score = round(max(0.0, min(100.0, risk_score)), 1)

    # Classify based on academic security thresholds
    if risk_score < 40.0:
        classification = "Safe / Legitimate"
        classification_slug = "safe"
        badge_class = "success"
        color_code = "#10b981"  # Emerald Green
    elif risk_score < 70.0:
        classification = "Suspicious"
        classification_slug = "suspicious"
        badge_class = "warning"
        color_code = "#f59e0b"  # Amber Orange
    else:
        classification = "High Risk / Potential Phishing"
        classification_slug = "danger"
        badge_class = "danger"
        color_code = "#ef4444"  # Crimson Red

    return {
        "success": True,
        "url": url_str,
        "normalized_url": analysis["components"]["normalized_url"],
        "classification": classification,
        "classification_slug": classification_slug,
        "badge_class": badge_class,
        "color_code": color_code,
        "risk_score": risk_score,
        "model_name": model_name,
        "model_mode": model_mode,
        "is_demo_mode": is_demo,
        "components": analysis["components"],
        "numerical_features": num_feats,
        "findings": analysis["findings"],
        "recommendations": analysis["recommendations"]
    }
