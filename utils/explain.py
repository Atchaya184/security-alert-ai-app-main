def get_alert_evidence(alert_dict, anomaly_score, rarity_score, recommendation):
    """
    Constructs auditable evidence and rules supporting the recommendation.
    """
    evidence = []
    
    # 1. Severity Evidence
    sev = alert_dict.get('severity', 'Medium')
    if sev in ['Critical', 'High']:
        evidence.append({
            'factor': 'Alert Severity',
            'value': sev,
            'impact': 'Escalation Trigger',
            'detail': f"Severity level '{sev}' prevents automated false positive closure."
        })
    else:
        evidence.append({
            'factor': 'Alert Severity',
            'value': sev,
            'impact': 'Benign Indicator',
            'detail': f"Severity '{sev}' is eligible for automated triage under safety guidelines."
        })
        
    # 2. Source IP Network Locality
    src_ip = str(alert_dict.get('source_ip', ''))
    is_external = not src_ip.startswith(('10.', '192.168.', '172.16.'))
    evidence.append({
        'factor': 'Source Network',
        'value': src_ip,
        'impact': 'High Risk' if is_external else 'Internal RFC1918',
        'detail': 'External origin address' if is_external else 'Internal corporate network origin'
    })
    
    # 3. Model Isolation Forest Score
    evidence.append({
        'factor': 'Isolation Forest Score',
        'value': f"{anomaly_score:.4f}",
        'impact': 'Normal Inlier' if anomaly_score >= 0.0 else 'Outlier Anomaly',
        'detail': 'Behavioral vector aligns with baseline activity.' if anomaly_score >= 0.0 else 'Behavioral vector deviates from normal cluster.'
    })
    
    # 4. Rarity Analysis
    evidence.append({
        'factor': 'Behavioral Rarity Score',
        'value': f"{rarity_score:.4f}",
        'impact': 'Familiar Pattern' if rarity_score >= 0.2 else 'Novel Combination',
        'detail': f"Historical familiarity metric is {rarity_score*100:.1f}%."
    })
    
    # 5. User Account Type
    user = str(alert_dict.get('user', ''))
    is_svc = user.startswith('svc_')
    evidence.append({
        'factor': 'User Context',
        'value': user,
        'impact': 'Service Account' if is_svc else 'Interactive User',
        'detail': 'Automated scheduled service credential' if is_svc else 'Interactive enterprise identity'
    })
    
    return evidence
