import numpy as np
import pandas as pd
from model.config import load_config

def compute_rarity_scores(df, preprocessor):
    """
    Computes normalized behavioral rarity score in range [0.0, 1.0] for security alerts.
    
    Behavioral Semantics:
    - Routine, frequent benign operations receive high familiarity scores (~0.6 - 1.0).
    - Rare, novel, or unique events receive low familiarity scores (< 0.20),
      requiring human analyst investigation even if anomaly score appears borderline.
    """
    scores = []
    for _, row in df.iterrows():
        # Epsilon fallback (0.001) ensures novel/unseen categorical values during runtime
        # do not trigger division-by-zero or zero-weight crashes; they are safely penalized
        # with near-zero frequency to signal high novelty/rarity.
        ef = preprocessor.event_freq.get(row.get('event_type'), 0.001)
        uf = preprocessor.user_freq.get(row.get('user'), 0.001)
        rf = preprocessor.rule_freq.get(row.get('rule_name', 'RULE-GENERAL'), 0.001)
        
        # Weighted combination of component frequencies:
        # - 0.45 (Event Type): Primary discriminator; core action pattern (e.g. scan vs auth spike).
        # - 0.30 (User Identity): Secondary discriminator; captures service account vs human persona.
        # - 0.25 (Detection Rule): Contextual discriminator; captures rule firing distribution across SOC.
        raw_score = (ef * 0.45) + (uf * 0.30) + (rf * 0.25)
        scores.append(raw_score)
        
    scores = np.array(scores)
    # Normalization floor guard: max(scores.max(), 0.05) avoids division-by-zero if all alerts
    # in a small batch are completely novel/unseen.
    max_val = max(scores.max(), 0.05) if len(scores) > 0 else 1.0
    normalized = scores / max_val
    # Clip output strictly within [0.0, 1.0] domain contract for downstream decision engine
    return np.clip(normalized, 0.0, 1.0)

def score_alert_anomaly(model, X_features):
    """
    Computes Isolation Forest decision function anomaly scores and discrete cluster predictions.
    
    Scoring Convention:
    - decision_function: Average depth of isolation trees.
      * Positive (> 0.0): Dense region, typical benign behavior (inlier).
      * Negative (< 0.0): Sparse region, isolated anomalous feature vector (outlier).
    - predict: Discrete cluster classification.
      * +1: Inlier (normal cluster).
      * -1: Outlier (anomalous sample isolated in fewer splits).
    """
    if model is None:
        # Fallback safeguard: if model artifact fails to load, default to conservative inlier baseline
        return 0.0, 1
    scores = model.decision_function(X_features)
    preds = model.predict(X_features)
    return scores, preds
