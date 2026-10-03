import pandas as pd
import numpy as np
import os
import joblib

SEVERITY_MAP = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}

class AlertPreprocessor:
    def __init__(self):
        self.event_freq = {}
        self.rule_freq = {}
        self.user_freq = {}
        self.is_fitted = False

    def fit(self, df):
        self.event_freq = df['event_type'].value_counts(normalize=True).to_dict()
        self.rule_freq = df['rule_name'].value_counts(normalize=True).to_dict()
        self.user_freq = df['user'].value_counts(normalize=True).to_dict()
        self.is_fitted = True
        return self

    def transform(self, df):
        if not self.is_fitted:
            raise ValueError("AlertPreprocessor must be fitted before transforming data.")
            
        df_copy = df.copy()
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
        features['is_external'] = (~df_copy['source_ip'].astype(str).str.startswith(('10.', '192.168.', '172.16.'))).astype(int)
        features['is_svc'] = df_copy['user'].astype(str).str.startswith('svc_').astype(int)
        features['is_admin'] = df_copy['user'].astype(str).str.contains('admin|root', case=False).astype(int)
        features['event_freq'] = df_copy['event_type'].map(lambda x: self.event_freq.get(x, 0.001))
        features['rule_freq'] = df_copy['rule_name'].map(lambda x: self.rule_freq.get(x, 0.001))
        features['user_freq'] = df_copy['user'].map(lambda x: self.user_freq.get(x, 0.001))
        
        return features

    def transform_single(self, alert_dict):
        df = pd.DataFrame([alert_dict])
        return self.transform(df)

    def save(self, filepath):
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath):
        if os.path.exists(filepath):
            return joblib.load(filepath)
        return cls()
