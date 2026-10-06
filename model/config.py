import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, 'model')
MODEL_PATH = os.path.join(MODEL_DIR, 'model.pkl')
CONFIG_PATH = os.path.join(MODEL_DIR, 'config.json')
METRICS_PATH = os.path.join(MODEL_DIR, 'metrics.json')

# Baseline Configuration (Before QBee improvement):
# Characterized by low contamination (0.01) and overly conservative rarity threshold (0.95),
# which limited automated false-positive reduction to only 3.33%.
BASELINE_CONFIG = {
    'version': 'v1.0.0-baseline',
    'model_name': 'Isolation Forest Baseline',
    # Contamination: Expected proportion of anomalies in dataset used to determine tree split offset
    'contamination': 0.01,
    # Rarity Threshold: Minimum behavioral familiarity required to consider alert routine
    'rarity_threshold': 0.95,
    # Score Threshold: Decision function cutoff below which an alert is deemed an anomaly
    'score_threshold': 0.258,
    'n_estimators': 100,
    'random_state': 42,
    # Invariant Safety Constraint: Under no circumstances may any true incident be dismissed
    'safety_threshold_missed_max': 0,
    # Target Metric: Must achieve >3.33% reduction rate across held-out evaluation
    'target_fp_reduction_min': 0.0333
}

# Fine-Tuned Configuration (After QBee Requirement 1):
# Optimized via systematic validation set grid search.
# Lowering rarity threshold to 0.15 and setting contamination to 0.05 expands the safe
# dismissal zone for genuine benign alerts while strictly preserving 0% missed incidents.
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
    """Loads active model configuration from config.json, falling back to TUNED_CONFIG."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return TUNED_CONFIG

def save_config(cfg):
    """Persists active model configuration to config.json."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(cfg, f, indent=2)

def load_metrics():
    """Loads recorded evaluation metrics and SOC benchmark statistics from metrics.json."""
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_metrics(metrics):
    """Persists evaluation metrics and validation experiment records to metrics.json."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    with open(METRICS_PATH, 'w') as f:
        json.dump(metrics, f, indent=2)
