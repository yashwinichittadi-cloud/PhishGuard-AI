"""
PhishGuard AI - Model Evaluation & Diagnostics Utility
Displays genuine calculated performance metrics and confusion matrices.
"""

import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import json
METRICS_PATH = os.path.join(BASE_DIR, "models", "model_metrics.json")


def get_evaluation_metrics():
    """Retrieves saved evaluation metrics or returns empty state if not yet trained."""
    if not os.path.exists(METRICS_PATH):
        return {
            "status": "not_trained",
            "message": "Model has not been trained yet. Please run 'python ml/train_model.py' to generate verified evaluation metrics."
        }

    try:
        with open(METRICS_PATH, "r") as f:
            metrics = json.load(f)
        metrics["status"] = "ready"
        return metrics
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error reading metrics file: {str(e)}"
        }


def print_cli_summary():
    """Prints a formatted evaluation table to the terminal."""
    metrics = get_evaluation_metrics()
    if metrics.get("status") != "ready":
        print(f"[!] {metrics.get('message')}")
        return

    print("=" * 70)
    print("PHISHGUARD AI - MACHINE LEARNING MODEL PERFORMANCE AUDIT")
    print("=" * 70)
    print(f"Dataset Size: {metrics['dataset']['total_urls']} URLs")
    print(f"Train/Test Split: {metrics['dataset']['train_samples']} Train / {metrics['dataset']['test_samples']} Test")
    print(f"Selected Champion Model: {metrics['champion_model']}")
    print("-" * 70)
    print(f"{'Model':<28} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 70)

    for key, data in metrics["models_evaluated"].items():
        print(f"{data['model_name']:<28} | {data['accuracy']:<10.4f} | {data['precision']:<10.4f} | {data['recall']:<10.4f} | {data['f1']:<10.4f}")
    print("=" * 70)


if __name__ == "__main__":
    print_cli_summary()
