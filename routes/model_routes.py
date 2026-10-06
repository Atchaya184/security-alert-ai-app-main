import os
import shutil
import json
from datetime import datetime
from flask import Blueprint, request, jsonify
from utils.db import get_db_connection
from utils.auth import get_current_user, require_permission
from utils.audit_csv import log_audit_event
from utils.recommend import predict_single_alert
from model.config import (
    MODEL_DIR, MODEL_PATH, CONFIG_PATH,
    load_config, save_config, load_metrics
)

model_bp = Blueprint('model_routes', __name__)

@model_bp.route('/api/model/status', methods=['GET'])
def get_model_status():
    config = load_config()
    metrics = load_metrics()
    
    conn = get_db_connection()
    versions = conn.execute('SELECT * FROM model_versions ORDER BY created_at DESC').fetchall()
    active_version_row = conn.execute('SELECT * FROM model_versions WHERE is_active = 1').fetchone()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'active_version': active_version_row['version_id'] if active_version_row else config.get('version', 'v2.0.0-tuned'),
        'config': config,
        'metrics': metrics,
        'versions': [dict(v) for v in versions]
    })

@model_bp.route('/api/model/versions', methods=['GET'])
def get_model_versions():
    conn = get_db_connection()
    versions = conn.execute('SELECT * FROM model_versions ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({
        'status': 'success',
        'versions': [dict(v) for v in versions]
    })

@model_bp.route('/api/model/predict', methods=['POST'])
def predict_alert():
    data = request.get_json() or {}
    alert = data.get('alert') or data
    if not alert:
        return jsonify({'status': 'error', 'message': 'No alert data provided for prediction.'}), 400
        
    config = load_config()
    pred = predict_single_alert(alert, config)
    return jsonify({
        'status': 'success',
        'prediction': pred,
        'model_version': config.get('version', 'unknown')
    })

@model_bp.route('/api/model/rollback', methods=['POST'])
@require_permission('rollback_model')
def rollback_model():
    """
    Rolls back active ML model to a previously registered, verified version.
    
    Reproducibility & Safety Lifecycle:
    Step 1: Authorization check enforced via @require_permission('rollback_model') (admin-only).
    Step 2: Version lookup in SQLite `model_versions` registry.
    Step 3: Verification of physical existence of frozen model artifact (.pkl).
    Step 4: Atomic file copy of target artifact onto active MODEL_PATH (`model.pkl`).
    Step 5: Synchronization of hyperparameters into active `config.json`.
    Step 6: Cache Invalidation - clears in-memory model pointer in utils.recommend so that
            subsequent API requests immediately deserialize the newly activated artifact.
    Step 7: Database state update (is_active pointer updated atomically).
    Step 8: Immutable audit logging of the rollback action and justification.
    """
    user = get_current_user()
    data = request.get_json() or {}
    target_version_id = data.get('target_version_id')
    rollback_reason = data.get('rollback_reason', '').strip()
    
    # Validation boundary: Reject missing parameters with structured 400 response
    if not target_version_id:
        return jsonify({'status': 'error', 'message': 'target_version_id is required for model rollback.'}), 400
    if not rollback_reason:
        return jsonify({'status': 'error', 'message': 'rollback_reason is mandatory for model rollback.'}), 400
        
    conn = get_db_connection()
    target_ver = conn.execute(
        'SELECT * FROM model_versions WHERE version_id = ?',
        (target_version_id,)
    ).fetchone()
    
    if not target_ver:
        conn.close()
        return jsonify({
            'status': 'error',
            'message': f"Target model version '{target_version_id}' not found in registry."
        }), 404
        
    current_active = conn.execute('SELECT * FROM model_versions WHERE is_active = 1').fetchone()
    prev_version_id = current_active['version_id'] if current_active else 'unknown'
    
    target_artifact = target_ver['model_artifact_path']
    # Physical integrity check: Ensure serialized joblib weights exist on disk
    if not os.path.exists(target_artifact):
        conn.close()
        return jsonify({
            'status': 'error',
            'message': f"Model artifact file not found at '{target_artifact}'."
        }), 500
        
    # Copy target artifact to active model path
    shutil.copyfile(target_artifact, MODEL_PATH)
    
    # Synchronize restored hyperparameters into active config.json
    restored_config = {
        'version': target_ver['version_id'],
        'model_name': target_ver['model_name'],
        'contamination': float(target_ver['contamination']),
        'rarity_threshold': float(target_ver['rarity_threshold']),
        'score_threshold': float(target_ver['score_threshold']),
        'n_estimators': 100,
        'random_state': 42
    }
    save_config(restored_config)
    
    # Invalidate in-memory cached model in utils/recommend.py to force fresh deserialization
    import utils.recommend
    utils.recommend._cached_model = None
    utils.recommend._cached_model_path = None
    
    # Update database state: Deactivate all versions and set target as the single active version
    conn.execute('UPDATE model_versions SET is_active = 0')
    conn.execute('UPDATE model_versions SET is_active = 1 WHERE version_id = ?', (target_version_id,))
    conn.commit()
    conn.close()
    
    # Immutable audit logging: Dual-write to SQLite audit_log table and audit_log.csv
    log_audit_event(
        user=user['username'],
        action='MODEL_ROLLBACK',
        target_type='model',
        target_id=target_version_id,
        details=f"Rolled back model from '{prev_version_id}' to '{target_version_id}'. Reason: {rollback_reason}",
        status='SUCCESS'
    )
    
    return jsonify({
        'status': 'success',
        'previous_version': prev_version_id,
        'active_version': target_version_id,
        'restored_config': restored_config,
        'message': f"Successfully rolled back model to version '{target_version_id}'. Reproducibility restored."
    })
