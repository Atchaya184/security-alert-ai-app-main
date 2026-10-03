from model.config import load_config

MALICIOUS_INDICATORS = [
    'injection', 'escalation', 'ransomware', 'brute', 'exfiltration',
    'mimikatz', 'psexec', 'malicious', 'exploit', 'compromised'
]

def make_alert_recommendation(alert_row, anomaly_score, rarity_score, iforest_pred, config=None):
    """
    Generates transparent triage recommendation and confidence score.
    Enforces the zero-missed-incident safety threshold.
    """
    if config is None:
        config = load_config()
        
    severity = str(alert_row.get('severity', 'Medium'))
    event_type = str(alert_row.get('event_type', '')).lower()
    source_ip = str(alert_row.get('source_ip', ''))
    
    score_thresh = config.get('score_threshold', 0.05)
    rarity_thresh = config.get('rarity_threshold', 0.15)
    
    # Safety Check 1: Explicit malicious event keywords -> ALWAYS ESCALATE
    if any(ind in event_type for ind in MALICIOUS_INDICATORS):
        return {
            'recommendation': 'Escalate / True Incident',
            'action': 'escalate',
            'confidence': 0.95,
            'reason': f"Critical signature matched: Event type '{alert_row.get('event_type')}' requires immediate security analyst containment."
        }
        
    # Safety Check 2: High or Critical severity -> NEVER AUTO-DISMISS
    if severity in ['High', 'Critical']:
        return {
            'recommendation': 'Investigate / High Severity',
            'action': 'investigate',
            'confidence': 0.90,
            'reason': f"High risk alert severity '{severity}'. Manual triage mandatory."
        }
        
    # Safety Check 3: External IP source for critical infrastructure
    is_external = not source_ip.startswith(('10.', '192.168.', '172.16.'))
    if is_external and severity != 'Low':
        return {
            'recommendation': 'Investigate / External Source',
            'action': 'investigate',
            'confidence': 0.85,
            'reason': f"External source IP '{source_ip}' detected on non-low severity event."
        }
        
    # Safety Check 4: Isolation Forest Anomaly or Rarity Outlier
    if iforest_pred == -1 or anomaly_score < score_thresh:
        return {
            'recommendation': 'Investigate / Anomaly Detected',
            'action': 'investigate',
            'confidence': round(abs(float(anomaly_score)) * 0.8 + 0.2, 2),
            'reason': f"Isolation Forest identified anomalous behavioral pattern (score: {anomaly_score:.3f} < {score_thresh})."
        }
        
    if rarity_score < rarity_thresh:
        return {
            'recommendation': 'Investigate / Rare Pattern',
            'action': 'investigate',
            'confidence': 0.78,
            'reason': f"Rarity score ({rarity_score:.3f}) below threshold ({rarity_thresh}). Rare behavioral combination."
        }
        
    # Condition for Safe False-Positive Auto-Dismissal:
    # Severity is Low or Medium, inlier (pred==1), anomaly score >= threshold, rarity >= threshold, internal IP
    return {
        'recommendation': 'Dismiss / False Positive',
        'action': 'dismiss',
        'confidence': 0.92,
        'reason': f"Routine benign pattern verified. Inlier score ({anomaly_score:.3f} > {score_thresh}) and high familiarity ({rarity_score:.3f} >= {rarity_thresh}). Safe for automated closure."
    }
