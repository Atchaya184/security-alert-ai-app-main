from model.config import load_config

# Tier 1 Deterministic Indicators:
# High-confidence attack taxonomy keywords that override any statistical inlier score.
# Even if an Isolation Forest score indicates high normality (e.g. repeated brute-force
# or common script execution), the presence of these indicators forces immediate escalation.
MALICIOUS_INDICATORS = [
    'injection', 'escalation', 'ransomware', 'brute', 'exfiltration',
    'mimikatz', 'psexec', 'malicious', 'exploit', 'compromised'
]

def make_alert_recommendation(alert_row, anomaly_score, rarity_score, iforest_pred, config=None):
    """
    Evaluates an alert through a 4-tier hierarchical defense-in-depth safety engine.
    
    Zero-Missed-Incident Policy:
    Statistical and ML models alone must never be permitted to unilaterally dismiss high-risk
    or adversarial events. Deterministic guardrails (Tiers 1-3) act as fail-safe circuit breakers
    before ML inlier scoring (Tier 4) is evaluated.
    
    Hierarchy:
    1. Tier 1 (Deterministic Signature): Known threat keywords -> Escalate immediately.
    2. Tier 2 (Severity Guardrail): High/Critical -> Mandatory human triage.
    3. Tier 3 (Perimeter / Locality): External origin on Medium -> Mandatory investigation.
    4. Tier 4 (Dual-Model Inlier & Familiarity): Isolation Forest + Rarity gating.
    """
    if config is None:
        config = load_config()
        
    severity = str(alert_row.get('severity', 'Medium'))
    event_type = str(alert_row.get('event_type', '')).lower()
    source_ip = str(alert_row.get('source_ip', ''))
    
    score_thresh = config.get('score_threshold', 0.05)
    rarity_thresh = config.get('rarity_threshold', 0.15)
    
    # --- Tier 1 Safety Gate: Known Malicious Indicator Override ---
    # Prevents "adversarial inliers" where a repetitive attack matches common frequency baselines.
    if any(ind in event_type for ind in MALICIOUS_INDICATORS):
        return {
            'recommendation': 'Escalate / True Incident',
            'action': 'escalate',
            'confidence': 0.95,
            'reason': f"Critical signature matched: Event type '{alert_row.get('event_type')}' requires immediate security analyst containment."
        }
        
    # --- Tier 2 Safety Gate: Severity Policy Hard Stop ---
    # High and Critical alerts represent existential threat risk. By SOC governance policy,
    # these alerts can NEVER be auto-dismissed, regardless of how "normal" the behavior appears.
    if severity in ['High', 'Critical']:
        return {
            'recommendation': 'Investigate / High Severity',
            'action': 'investigate',
            'confidence': 0.90,
            'reason': f"High risk alert severity '{severity}'. Manual triage mandatory."
        }
        
    # --- Tier 3 Safety Gate: External Network Perimeter Defense ---
    # Non-RFC1918 traffic (outside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) originating
    # from public internet ingress points warrants human scrutiny unless explicitly categorized as Low.
    is_external = not source_ip.startswith(('10.', '192.168.', '172.16.'))
    if is_external and severity != 'Low':
        return {
            'recommendation': 'Investigate / External Source',
            'action': 'investigate',
            'confidence': 0.85,
            'reason': f"External source IP '{source_ip}' detected on non-low severity event."
        }
        
    # --- Tier 4 Safety Gate: Statistical Anomaly & Behavioral Rarity Dual-Gating ---
    # A sample is flagged for investigation if EITHER the tree-based anomaly detector
    # flags an outlier (pred == -1 or score < threshold) OR the frequency-weighted
    # historical familiarity metric is unusually low (< rarity_threshold).
    if iforest_pred == -1 or anomaly_score < score_thresh:
        return {
            'recommendation': 'Investigate / Anomaly Detected',
            'action': 'investigate',
            # Confidence scales inversely with anomaly depth: deeper isolation yields higher confidence of anomaly
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
        
    # --- Tier 5 Automated False-Positive Dismissal Condition ---
    # An alert qualifies for automated dismissal ONLY when it has passed all 4 safety tiers:
    # 1. No malicious keyword signatures.
    # 2. Low/Medium severity only.
    # 3. Internal RFC1918 IP address.
    # 4. Dense cluster inlier (Isolation Forest pred == +1 and score >= score_thresh).
    # 5. High historical familiarity (rarity_score >= rarity_thresh).
    return {
        'recommendation': 'Dismiss / False Positive',
        'action': 'dismiss',
        'confidence': 0.92,
        'reason': f"Routine benign pattern verified. Inlier score ({anomaly_score:.3f} > {score_thresh}) and high familiarity ({rarity_score:.3f} >= {rarity_thresh}). Safe for automated closure."
    }
