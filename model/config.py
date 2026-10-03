import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, 'model')
MODEL_PATH = os.path.join(MODEL_DIR, 'model.pkl')
CONFIG_PATH = os.path.join(MODEL_DIR, 'config.json')
METRICS_PATH = os.path.join(MODEL_DIR, 'metrics.json')

# Baseline Configuration (Before QBee improvement)
BASELINE_CONFIG = {
    'version': 'v1.0.0-baseline',
    'model_name': 'Isolation Forest Baseline',
    'contamination': 0.01,
    'rarity_threshold': 0.95,
    'score_threshold': 0.258,
    'n_estimators': 100,
    'random_state': 42,
    'safety_threshold_missed_max': 0,
    'target_fp_reduction_min': 0.0333
}

# Fine-Tuned Configuration (After QBee Requirement 1)
# Elevated FP reduction rate well beyond 3.33% while preserving strict 0% missed incident threshold
TUNED_CONFIG = {
    'version': 'v2.0.0-tuned',
    'model_name': 'Isolation Forest Tuned',
    'contamination': 0.05,
    'rarity_threshold': 0.15,
    'score_threshold': 0.05,
    'n_estimators': 100,
    'random_state': 42,
    'safety_threshold_missed_max': 0,
    'target_fp_reduction_min': 0.0333
}

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return TUNED_CONFIG

def save_config(cfg):
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(cfg, f, indent=2)

def load_metrics():
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_metrics(metrics):
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(METRICS_PATH, 'w') as f:
        json.dump(metrics, f, indent=2)
