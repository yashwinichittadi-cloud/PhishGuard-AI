"""
PhishGuard AI - Machine Learning Model Training & Evaluation Engine
Trains Logistic Regression & Random Forest models on verified datasets,
evaluates genuine performance metrics, and serializes the champion model.
"""

import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import json
import numpy as np
import pandas as pd
import joblib
from scipy.sparse import hstack
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from ml.feature_extraction import extract_numerical_features
DATASET_PATH = os.path.join(BASE_DIR, "data", "dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "trained_model.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "model_metrics.json")


def load_dataset(filepath=DATASET_PATH):
    """Loads and validates the URL dataset, removing duplicates to prevent data leakage."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset file not found at: {filepath}")

    df = pd.read_csv(filepath)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    # Drop any nulls and duplicate URLs to ensure zero test set leakage
    initial_count = len(df)
    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    cleaned_count = len(df)

    print(f"[+] Dataset loaded: {cleaned_count} distinct URLs ({initial_count - cleaned_count} duplicates removed).")
    print(f"    Class distribution: Legitimate (0)={sum(df['label'] == 0)}, Phishing (1)={sum(df['label'] == 1)}")
    return df


def extract_batch_features(url_list):
    """Extracts numerical features for a list of URLs into a DataFrame."""
    feature_rows = [extract_numerical_features(u) for u in url_list]
    df_features = pd.DataFrame(feature_rows)
    return df_features


def train_and_evaluate():
    """Executes the complete ML pipeline, comparing two distinct algorithms."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    df = load_dataset(DATASET_PATH)

    urls = df["url"].values
    labels = df["label"].values

    # Stratified Train-Test Split (80% Train, 20% Held-out Test)
    train_urls, test_urls, y_train, y_test = train_test_split(
        urls, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print(f"[+] Stratified Split complete: {len(train_urls)} Train samples, {len(test_urls)} Test samples.")

    # 1. Numerical Feature Extraction
    print("[+] Extracting 16 lexical and structural numerical features...")
    df_feat_train = extract_batch_features(train_urls)
    df_feat_test = extract_batch_features(test_urls)
    feature_names = list(df_feat_train.columns)

    scaler = StandardScaler()
    X_num_train = scaler.fit_transform(df_feat_train)
    X_num_test = scaler.transform(df_feat_test)

    # 2. Character-level TF-IDF (3 to 5 character n-grams)
    print("[+] Fitting Character-level TF-IDF Vectorizer (ngram_range=(3,5), max_features=800)...")
    tfidf = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        max_features=800,
        sublinear_tf=True
    )
    X_tfidf_train = tfidf.fit_transform(train_urls)
    X_tfidf_test = tfidf.transform(test_urls)

    # 3. Hybrid Feature Combination (Stacking numerical and n-gram TF-IDF)
    X_train_combined = hstack([X_num_train, X_tfidf_train]).tocsr()
    X_test_combined = hstack([X_num_test, X_tfidf_test]).tocsr()
    print(f"[+] Combined feature matrix shape: Train={X_train_combined.shape}, Test={X_test_combined.shape}")

    # Candidate 1: Logistic Regression
    print("\n--- Training Model 1: Logistic Regression ---")
    lr_model = LogisticRegression(max_iter=1000, random_state=42, class_weight="balanced")
    lr_model.fit(X_train_combined, y_train)
    y_pred_lr = lr_model.predict(X_test_combined)

    metrics_lr = {
        "model_name": "Logistic Regression",
        "accuracy": round(float(accuracy_score(y_test, y_pred_lr)), 4),
        "precision": round(float(precision_score(y_test, y_pred_lr, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred_lr, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, y_pred_lr, zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred_lr).tolist()
    }
    print(f"    Logistic Regression -> Acc: {metrics_lr['accuracy']:.4f}, Prec: {metrics_lr['precision']:.4f}, Rec: {metrics_lr['recall']:.4f}, F1: {metrics_lr['f1']:.4f}")

    # Candidate 2: Random Forest
    print("\n--- Training Model 2: Random Forest Classifier ---")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, class_weight="balanced")
    rf_model.fit(X_train_combined, y_train)
    y_pred_rf = rf_model.predict(X_test_combined)

    metrics_rf = {
        "model_name": "Random Forest Classifier",
        "accuracy": round(float(accuracy_score(y_test, y_pred_rf)), 4),
        "precision": round(float(precision_score(y_test, y_pred_rf, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred_rf, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, y_pred_rf, zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred_rf).tolist()
    }
    print(f"    Random Forest -> Acc: {metrics_rf['accuracy']:.4f}, Prec: {metrics_rf['precision']:.4f}, Rec: {metrics_rf['recall']:.4f}, F1: {metrics_rf['f1']:.4f}")

    # Determine Champion Model based on F1-Score
    if metrics_rf["f1"] >= metrics_lr["f1"]:
        champion_model = rf_model
        champion_name = "Random Forest Classifier"
        champion_metrics = metrics_rf
    else:
        champion_model = lr_model
        champion_name = "Logistic Regression"
        champion_metrics = metrics_lr

    print(f"\n[+] Selected Champion Model: {champion_name} (F1: {champion_metrics['f1']:.4f})")

    # Serialize Model Artifact
    artifact = {
        "model": champion_model,
        "scaler": scaler,
        "tfidf": tfidf,
        "feature_names": feature_names,
        "model_name": champion_name,
        "version": "1.0.0"
    }
    joblib.dump(artifact, MODEL_PATH)
    print(f"[+] Serialized model successfully saved to: {MODEL_PATH}")

    # Save comprehensive metrics json for web dashboard and viva evaluation
    evaluation_report = {
        "timestamp": pd.Timestamp.now().isoformat(),
        "dataset": {
            "total_urls": len(df),
            "train_samples": len(train_urls),
            "test_samples": len(test_urls),
            "legitimate_count": int(sum(df["label"] == 0)),
            "phishing_count": int(sum(df["label"] == 1)),
            "test_distribution": {
                "legitimate": int(sum(y_test == 0)),
                "phishing": int(sum(y_test == 1))
            }
        },
        "champion_model": champion_name,
        "models_evaluated": {
            "logistic_regression": metrics_lr,
            "random_forest": metrics_rf
        },
        "feature_count": {
            "numerical": len(feature_names),
            "tfidf_ngrams": X_tfidf_train.shape[1],
            "total_features": X_train_combined.shape[1]
        }
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(evaluation_report, f, indent=2)
    print(f"[+] Model metrics saved to: {METRICS_PATH}")
    return evaluation_report


if __name__ == "__main__":
    train_and_evaluate()
