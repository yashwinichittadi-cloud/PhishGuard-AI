import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "phishguard-ai-secret-key-cybersec-2026")
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "phishguard.db")
    DATASET_PATH = os.path.join(BASE_DIR, "data", "dataset.csv")
    MODEL_DIR = os.path.join(BASE_DIR, "models")
    MODEL_PATH = os.path.join(MODEL_DIR, "trained_model.joblib")
    METRICS_PATH = os.path.join(MODEL_DIR, "model_metrics.json")
    
    # ML Hyperparameters & Config
    RANDOM_STATE = 42
    TEST_SIZE = 0.2
    
    # App Information
    APP_NAME = "PhishGuard AI"
    TAGLINE = "Intelligent Phishing Detection & Cybersecurity Analysis Platform"
    VERSION = "1.0.0"
