import numpy as np
import pandas as pd
from model.config import load_config

def compute_rarity_scores(df, preprocessor):
    """
    Computes normalized rarity score [0.0, 1.0] for security alerts.
    Routine, frequent benign operations have high rarity scores (~0.6 - 1.0).
    Rare, novel, or unique events have low rarity scores (< 0.2).
    """
    scores = []
    for _, row in df.iterrows():
        ef = preprocessor.event_freq.get(row.get('event_type'), 0.001)
        uf = preprocessor.user_freq.get(row.get('user'), 0.001)
        rf = preprocessor.rule_freq.get(row.get('rule_name', 'RULE-GENERAL'), 0.001)
        
        # Weighted combination of component frequencies
        raw_score = (ef * 0.45) + (uf * 0.30) + (rf * 0.25)
        scores.append(raw_score)
        
    scores = np.array(scores)
    max_val = max(scores.max(), 0.05) if len(scores) > 0 else 1.0
    normalized = scores / max_val
    return np.clip(normalized, 0.0, 1.0)

def score_alert_anomaly(model, X_features):
    """
    Returns the Isolation Forest decision function score (higher = normal, lower = anomaly)
    and binary prediction (+1 for inlier, -1 for outlier anomaly).
    """
    if model is None:
        return 0.0, 1
    scores = model.decision_function(X_features)
    preds = model.predict(X_features)
    return scores, preds
