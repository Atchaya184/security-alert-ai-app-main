import joblib
import os
import pandas as pd
from model.config import MODEL_PATH, load_config
from model.preprocess import AlertPreprocessor, SEVERITY_MAP
from model.novelty import compute_rarity_scores, score_alert_anomaly
from model.decision import make_alert_recommendation

PREPROCESSOR_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'model', 'preprocessor.pkl')

_cached_model = None
_cached_preprocessor = None
_cached_model_path = None

def get_model():
    global _cached_model, _cached_model_path
    if _cached_model is None or _cached_model_path != MODEL_PATH or not os.path.exists(MODEL_PATH):
        if os.path.exists(MODEL_PATH):
            _cached_model = joblib.load(MODEL_PATH)
            _cached_model_path = MODEL_PATH
    return _cached_model

def get_preprocessor():
    global _cached_preprocessor
    if _cached_preprocessor is None:
        if os.path.exists(PREPROCESSOR_PATH):
            _cached_preprocessor = AlertPreprocessor.load(PREPROCESSOR_PATH)
        else:
            _cached_preprocessor = AlertPreprocessor()
    return _cached_preprocessor

def predict_single_alert(alert_dict, config=None):
    """
    Evaluates an alert through the active preprocessor, Isolation Forest model,
    rarity scorer, and decision safety threshold.
    """
    if config is None:
        config = load_config()
        
    model = get_model()
    preprocessor = get_preprocessor()
    
    safe_alert = dict(alert_dict)
    if 'rule_name' not in safe_alert or not safe_alert['rule_name']:
        safe_alert['rule_name'] = 'RULE-GENERAL'
    if 'destination_ip' not in safe_alert or not safe_alert['destination_ip']:
        safe_alert['destination_ip'] = '10.0.0.1'
    if 'severity' not in safe_alert or not safe_alert['severity']:
        safe_alert['severity'] = 'Medium'
        
    df = pd.DataFrame([safe_alert])
    
    if preprocessor.is_fitted:
        X = preprocessor.transform(df)
        rarity_scores = compute_rarity_scores(df, preprocessor)
        rarity_score = float(rarity_scores[0])
    else:
        # Fallback if preprocessor not fitted
        X = pd.DataFrame([{
            'severity_num': SEVERITY_MAP.get(alert_dict.get('severity', 'Medium'), 2),
            'is_external': int(not str(alert_dict.get('source_ip', '')).startswith(('10.', '192.168.', '172.16.'))),
            'is_svc': int(str(alert_dict.get('user', '')).startswith('svc_')),
            'is_admin': int('admin' in str(alert_dict.get('user', '')).lower() or 'root' in str(alert_dict.get('user', '')).lower()),
            'event_freq': 0.05,
            'rule_freq': 0.05,
            'user_freq': 0.05
        }])
        rarity_score = 0.5
        
    anomaly_scores, preds = score_alert_anomaly(model, X)
    anomaly_score = float(anomaly_scores[0])
    pred = int(preds[0])
    
    rec = make_alert_recommendation(alert_dict, anomaly_score, rarity_score, pred, config)
    
    return {
        'recommendation': rec['recommendation'],
        'action': rec['action'],
        'confidence': rec['confidence'],
        'reason': rec['reason'],
        'anomaly_score': round(anomaly_score, 4),
        'rarity_score': round(rarity_score, 4),
        'iforest_prediction': pred
    }
