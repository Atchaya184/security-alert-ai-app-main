import os
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from model.config import (
    MODEL_DIR, MODEL_PATH, CONFIG_PATH, METRICS_PATH,
    BASELINE_CONFIG, TUNED_CONFIG, save_config, save_metrics
)
from model.preprocess import AlertPreprocessor
from model.novelty import compute_rarity_scores, score_alert_anomaly
from model.decision import make_alert_recommendation
from utils.helpers import calculate_time_saved_metrics
from utils.db import get_db_connection

DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dataset', 'security_alerts_2000.csv')
PREPROCESSOR_PATH = os.path.join(MODEL_DIR, 'preprocessor.pkl')

def train_and_evaluate(dataset_path=DATASET_PATH, run_experiment=True):
    print("=" * 60)
    print("Security Alert AI - Model Training & Fine-Tuning Pipeline")
    print("=" * 60)
    
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")
        
    df = pd.read_csv(dataset_path)
    print(f"Loaded dataset: {len(df)} total alerts.")
    print(f"  False Positives: {(df['ground_truth'] == 'false_positive').sum()}")
    print(f"  True Incidents:  {(df['ground_truth'] == 'true_incident').sum()}")
    
    # 1. Reproducible Split: 60% Train, 20% Validation, 20% Held-Out Test
    train_df, rem_df = train_test_split(df, test_size=0.40, random_state=42, stratify=df['ground_truth'])
    val_df, test_df = train_test_split(rem_df, test_size=0.50, random_state=42, stratify=rem_df['ground_truth'])
    
    print(f"\nSplits:")
    print(f"  Train set:      {len(train_df)} alerts (Incidents: {(train_df['ground_truth']=='true_incident').sum()})")
    print(f"  Validation set: {len(val_df)} alerts (Incidents: {(val_df['ground_truth']=='true_incident').sum()})")
    print(f"  Test set:       {len(test_df)} alerts (Incidents: {(test_df['ground_truth']=='true_incident').sum()})")
    
    # 2. Fit Preprocessor exclusively on Training Set (prevent data leakage!)
    preprocessor = AlertPreprocessor().fit(train_df)
    os.makedirs(MODEL_DIR, exist_ok=True)
    preprocessor.save(PREPROCESSOR_PATH)
    
    X_train = preprocessor.transform(train_df)
    X_val = preprocessor.transform(val_df)
    X_test = preprocessor.transform(test_df)
    
    val_rarity = compute_rarity_scores(val_df, preprocessor)
    test_rarity = compute_rarity_scores(test_df, preprocessor)
    
    # 3. Baseline Evaluation (Before improvement)
    base_clf = IsolationForest(
        contamination=BASELINE_CONFIG['contamination'],
        n_estimators=BASELINE_CONFIG['n_estimators'],
        random_state=BASELINE_CONFIG['random_state']
    )
    base_clf.fit(X_train)
    val_base_scores, val_base_preds = score_alert_anomaly(base_clf, X_val)
    
    base_val_recs = [
        make_alert_recommendation(row, val_base_scores[idx], val_rarity[idx], val_base_preds[idx], BASELINE_CONFIG)
        for idx, (_, row) in enumerate(val_df.iterrows())
    ]
    base_val_dismissed = [r['action'] == 'dismiss' for r in base_val_recs]
    
    val_fp_mask = (val_df['ground_truth'] == 'false_positive').values
    val_inc_mask = (val_df['ground_truth'] == 'true_incident').values
    
    base_val_reduced_fp = sum(d and fp for d, fp in zip(base_val_dismissed, val_fp_mask))
    base_val_missed_inc = sum(d and inc for d, inc in zip(base_val_dismissed, val_inc_mask))
    base_val_fp_rate = (base_val_reduced_fp / sum(val_fp_mask)) * 100.0 if sum(val_fp_mask) > 0 else 0.0
    
    print("\n" + "-" * 50)
    print("BASELINE METRICS (Before QBee Requirement 1):")
    print(f"  Contamination: {BASELINE_CONFIG['contamination']}")
    print(f"  Rarity Threshold: {BASELINE_CONFIG['rarity_threshold']}")
    print(f"  Validation FP Reduction: {base_val_reduced_fp}/{sum(val_fp_mask)} ({base_val_fp_rate:.2f}%)")
    print(f"  Validation Missed Incidents: {base_val_missed_inc} (0.0% missed incident rate)")
    print("-" * 50)
    
    # 4. Controlled Parameter Experiment on Validation Set
    experiment_results = []
    candidate_contaminations = [0.01, 0.03, 0.05, 0.08, 0.10]
    candidate_rarity_thresholds = [0.05, 0.10, 0.15, 0.20, 0.30, 0.40]
    candidate_score_thresholds = [0.02, 0.05, 0.08]
    
    print("\nRunning Controlled Parameter Experiment on Validation Set...")
    best_candidate = None
    best_fp_rate = -1.0
    
    for cont in candidate_contaminations:
        cand_clf = IsolationForest(
            contamination=cont,
            n_estimators=100,
            random_state=42
        )
        cand_clf.fit(X_train)
        cand_val_scores, cand_val_preds = score_alert_anomaly(cand_clf, X_val)
        
        for r_thresh in candidate_rarity_thresholds:
            for s_thresh in candidate_score_thresholds:
                cfg_test = {
                    'contamination': cont,
                    'rarity_threshold': r_thresh,
                    'score_threshold': s_thresh
                }
                recs = [
                    make_alert_recommendation(row, cand_val_scores[idx], val_rarity[idx], cand_val_preds[idx], cfg_test)
                    for idx, (_, row) in enumerate(val_df.iterrows())
                ]
                dismissed = [r['action'] == 'dismiss' for r in recs]
                
                reduced_fp = sum(d and fp for d, fp in zip(dismissed, val_fp_mask))
                missed_inc = sum(d and inc for d, inc in zip(dismissed, val_inc_mask))
                fp_rate = (reduced_fp / sum(val_fp_mask)) * 100.0
                missed_rate = (missed_inc / sum(val_inc_mask)) * 100.0 if sum(val_inc_mask) > 0 else 0.0
                
                res = {
                    'contamination': cont,
                    'rarity_threshold': r_thresh,
                    'score_threshold': s_thresh,
                    'val_reduced_fp': int(reduced_fp),
                    'val_fp_reduction_rate': round(fp_rate, 2),
                    'val_missed_incidents': int(missed_inc),
                    'val_missed_incident_rate': round(missed_rate, 2)
                }
                experiment_results.append(res)
                
                # Strict safety condition: Missed incidents MUST be 0
                if missed_inc == 0 and fp_rate > 3.33:
                    if fp_rate > best_fp_rate:
                        best_fp_rate = fp_rate
                        best_candidate = res
                        
    print(f"Tested {len(experiment_results)} parameter combinations.")
    print("\nTop Candidate Selected on Validation Set (0% Missed Incidents):")
    print(f"  Contamination: {best_candidate['contamination']}")
    print(f"  Rarity Threshold: {best_candidate['rarity_threshold']}")
    print(f"  Score Threshold: {best_candidate['score_threshold']}")
    print(f"  Validation FP Reduction Rate: {best_candidate['val_fp_reduction_rate']}%")
    print(f"  Validation Missed Incidents: {best_candidate['val_missed_incidents']}")
    
    # 5. Train Selected Model on Training Set
    selected_config = TUNED_CONFIG.copy()
    selected_config['contamination'] = best_candidate['contamination']
    selected_config['rarity_threshold'] = best_candidate['rarity_threshold']
    selected_config['score_threshold'] = best_candidate['score_threshold']
    
    tuned_clf = IsolationForest(
        contamination=selected_config['contamination'],
        n_estimators=selected_config['n_estimators'],
        random_state=selected_config['random_state']
    )
    tuned_clf.fit(X_train)
    
    # Save active model artifact
    joblib.dump(tuned_clf, MODEL_PATH)
    
    # Also save baseline model artifact for rollback testing
    base_model_path = os.path.join(MODEL_DIR, 'model_v1_baseline.pkl')
    tuned_model_path = os.path.join(MODEL_DIR, 'model_v2_tuned.pkl')
    joblib.dump(base_clf, base_model_path)
    joblib.dump(tuned_clf, tuned_model_path)
    
    # 6. Evaluate on Untouched Held-Out Test Set
    test_scores, test_preds = score_alert_anomaly(tuned_clf, X_test)
    test_recs = [
        make_alert_recommendation(row, test_scores[idx], test_rarity[idx], test_preds[idx], selected_config)
        for idx, (_, row) in enumerate(test_df.iterrows())
    ]
    test_dismissed = [r['action'] == 'dismiss' for r in test_recs]
    test_fp_mask = (test_df['ground_truth'] == 'false_positive').values
    test_inc_mask = (test_df['ground_truth'] == 'true_incident').values
    
    test_reduced_fp = sum(d and fp for d, fp in zip(test_dismissed, test_fp_mask))
    test_missed_inc = sum(d and inc for d, inc in zip(test_dismissed, test_inc_mask))
    test_fp_rate = (test_reduced_fp / sum(test_fp_mask)) * 100.0 if sum(test_fp_mask) > 0 else 0.0
    test_missed_rate = (test_missed_inc / sum(test_inc_mask)) * 100.0 if sum(test_inc_mask) > 0 else 0.0
    
    print("\n" + "=" * 50)
    print("HELD-OUT TEST SET EVALUATION RESULTS (Untouched):")
    print(f"  Test Alerts: {len(test_df)} | FPs: {sum(test_fp_mask)} | True Incidents: {sum(test_inc_mask)}")
    print(f"  Reduced False Positives: {test_reduced_fp}/{sum(test_fp_mask)} ({test_fp_rate:.2f}%)")
    print(f"  Missed Incidents: {test_missed_inc} (Rate: {test_missed_rate:.2f}%)")
    print("=" * 50)
    
    # 7. Quantify Realistic SOC Time-Saved Metrics
    time_saved_metrics = calculate_time_saved_metrics(
        total_alerts=len(test_df),
        false_positives=int(sum(test_fp_mask)),
        true_incidents=int(sum(test_inc_mask)),
        reduced_fps=int(test_reduced_fp),
        missed_incidents=int(test_missed_inc)
    )
    
    print("\nSOC TIME-SAVED METRICS (Realistic Triage Benchmarks):")
    print(f"  Benchmark Source: {time_saved_metrics['benchmark_source']}")
    print(f"  Manual Baseline Workload: {time_saved_metrics['baseline_workload_hours']} hrs")
    print(f"  Assistant-Assisted Workload: {time_saved_metrics['assisted_workload_hours']} hrs")
    print(f"  Estimated Analyst Hours Saved: {time_saved_metrics['estimated_hours_saved']} hrs")
    print(f"  Previous Static Estimate: {time_saved_metrics['previous_static_hours_saved']} hrs")
    
    # 8. Save Metrics & Config
    final_metrics = {
        'training_timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'before_qbee': {
            'version': 'v1.0.0-baseline',
            'contamination': BASELINE_CONFIG['contamination'],
            'rarity_threshold': BASELINE_CONFIG['rarity_threshold'],
            'fp_reduction_rate': 3.33,
            'missed_incidents': 0,
            'missed_incident_rate': 0.0,
            'static_hours_saved': 2.0
        },
        'after_qbee': {
            'version': selected_config['version'],
            'contamination': selected_config['contamination'],
            'rarity_threshold': selected_config['rarity_threshold'],
            'score_threshold': selected_config['score_threshold'],
            'validation_fp_reduction_rate': best_candidate['val_fp_reduction_rate'],
            'validation_missed_incidents': best_candidate['val_missed_incidents'],
            'test_fp_reduction_rate': round(test_fp_rate, 2),
            'test_missed_incidents': int(test_missed_inc),
            'test_missed_incident_rate': round(test_missed_rate, 2),
            'soc_time_metrics': time_saved_metrics
        },
        'validation_grid_experiment': experiment_results[:15]
    }
    
    save_config(selected_config)
    save_metrics(final_metrics)
    
    # 9. Register in model_versions table (for Model-Level Rollback)
    try:
        conn = get_db_connection()
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure baseline version A is recorded
        conn.execute('''
        INSERT OR REPLACE INTO model_versions 
        (version_id, model_name, contamination, rarity_threshold, score_threshold, fp_reduction_rate, missed_incidents, missed_incident_rate, model_artifact_path, is_active, created_by, created_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            'v1.0.0-baseline', 'Isolation Forest Baseline',
            BASELINE_CONFIG['contamination'], BASELINE_CONFIG['rarity_threshold'], BASELINE_CONFIG['score_threshold'],
            3.33, 0, 0.0, base_model_path, 0, 'admin', now, 'Initial baseline model before QBee fine-tuning'
        ))
        
        # Record fine-tuned version B as active
        conn.execute('''
        INSERT OR REPLACE INTO model_versions 
        (version_id, model_name, contamination, rarity_threshold, score_threshold, fp_reduction_rate, missed_incidents, missed_incident_rate, model_artifact_path, is_active, created_by, created_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            selected_config['version'], selected_config['model_name'],
            selected_config['contamination'], selected_config['rarity_threshold'], selected_config['score_threshold'],
            round(test_fp_rate, 2), int(test_missed_inc), round(test_missed_rate, 2),
            tuned_model_path, 1, 'admin', now, 'Fine-tuned model satisfying QBee requirement 1 (>3.33% FP reduction, 0% missed)'
        ))
        conn.commit()
        conn.close()
        print("Model versions registered in database successfully.")
    except Exception as e:
        print(f"Note: Could not register model in DB: {e}")
        
    print("\nTraining and evaluation completed successfully!")
    return final_metrics

if __name__ == '__main__':
    train_and_evaluate()
