import pandas as pd
import numpy as np
import os
import joblib

# Ordinal mapping representing increasing severity risk level
SEVERITY_MAP = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}

class AlertPreprocessor:
    """
    Feature engineering pipeline for tabular security alert telemetry.
    
    Data Leakage Contract:
    - Must be fitted strictly on the training partition (`train_df`).
    - Validation and test sets, as well as live streaming alerts, must only
      be transformed using the pre-computed training marginal distributions.
    """
    def __init__(self):
        self.event_freq = {}
        self.rule_freq = {}
        self.user_freq = {}
        self.is_fitted = False

    def fit(self, df):
        """
        Computes marginal normalized frequencies on training set.
        These act as the baseline reference distributions for frequency encoding.
        """
        self.event_freq = df['event_type'].value_counts(normalize=True).to_dict()
        self.rule_freq = df['rule_name'].value_counts(normalize=True).to_dict()
        self.user_freq = df['user'].value_counts(normalize=True).to_dict()
        self.is_fitted = True
        return self

    def transform(self, df):
        """
        Constructs numeric feature matrix for Isolation Forest anomaly scoring:
        1. severity_num: Ordinal risk score (1 to 4).
        2. is_external: Binary flag for non-RFC1918 traffic (identifies external internet ingress).
        3. is_svc: Binary flag identifying service accounts (`svc_`), which have regular machine patterns.
        4. is_admin: Binary flag identifying privileged credentials (`admin`, `root`).
        5. event_freq: Historical baseline probability of the alert's event type.
        6. rule_freq: Historical baseline probability of the detection rule firing.
        7. user_freq: Historical baseline probability of the account triggering alerts.
        """
        if not self.is_fitted:
            raise ValueError("AlertPreprocessor must be fitted before transforming data.")
            
        df_copy = df.copy()
        # Defensive fallback defaults to prevent null pointer exceptions on sparse incoming alerts
        if 'severity' not in df_copy.columns:
            df_copy['severity'] = 'Medium'
        if 'source_ip' not in df_copy.columns:
            df_copy['source_ip'] = '10.0.0.1'
        if 'user' not in df_copy.columns:
            df_copy['user'] = 'unknown'
        if 'event_type' not in df_copy.columns:
            df_copy['event_type'] = 'General Alert'
        if 'rule_name' not in df_copy.columns:
            df_copy['rule_name'] = 'RULE-GENERAL'
            
        features = pd.DataFrame(index=df_copy.index)
        features['severity_num'] = df_copy['severity'].map(lambda x: SEVERITY_MAP.get(x, 2))
        # External IP detection: addresses outside standard RFC 1918 private subnets
        features['is_external'] = (~df_copy['source_ip'].astype(str).str.startswith(('10.', '192.168.', '172.16.'))).astype(int)
        # Service accounts typically run scheduled automated tasks (high volume, low risk)
        features['is_svc'] = df_copy['user'].astype(str).str.startswith('svc_').astype(int)
        # Privileged accounts represent high lateral movement / compromise target risk
        features['is_admin'] = df_copy['user'].astype(str).str.contains('admin|root', case=False).astype(int)
        # Frequency encoding maps categorical strings into continuous rarity dimensions (default epsilon 0.001)
        features['event_freq'] = df_copy['event_type'].map(lambda x: self.event_freq.get(x, 0.001))
        features['rule_freq'] = df_copy['rule_name'].map(lambda x: self.rule_freq.get(x, 0.001))
        features['user_freq'] = df_copy['user'].map(lambda x: self.user_freq.get(x, 0.001))
        
        return features

    def transform_single(self, alert_dict):
        """Transforms a single alert dictionary for real-time inference."""
        df = pd.DataFrame([alert_dict])
        return self.transform(df)

    def save(self, filepath):
        """Serializes fitted preprocessor state using joblib."""
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath):
        """Restores fitted preprocessor state from serialized artifact."""
        if os.path.exists(filepath):
            return joblib.load(filepath)
        return cls()
