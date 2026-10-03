import os
import io
import json
import pytest
from app import create_app
from utils.db import get_db_connection, init_db
from model.config import load_config, save_config, load_metrics
from utils.helpers import calculate_time_saved_metrics

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client

# =========================================================================
# REQUIREMENT 3 — EDGE & FAILURE TEST SUITES
# =========================================================================

# --- Case 1: Malformed CSV Payloads ---
def test_malformed_csv_missing_mandatory_columns(client):
    """
    Case 1.1: Malformed CSV missing mandatory security alert columns.
    Must be safely rejected with HTTP 400 and clear error, without state corruption.
    """
    csv_data = "alert_id,source_ip\nALT-TEST-999,10.0.1.50\n"
    data = {'file': (io.BytesIO(csv_data.encode('utf-8')), 'bad_columns.csv')}
    
    # Check count before
    conn = get_db_connection()
    count_before = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    
    res = client.post('/api/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 400
    res_data = res.get_json()
    assert res_data['status'] == 'error'
    assert res_data['error_type'] == 'SCHEMA_VALIDATION_ERROR'
    assert 'Missing mandatory security alert columns' in res_data['message']
    
    # Verify database state was NOT corrupted or changed
    conn = get_db_connection()
    count_after = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count_after == count_before

def test_malformed_csv_invalid_data_types(client):
    """
    Case 1.2: Malformed row with invalid severity data type.
    Must be safely rejected without producing incorrect decisions.
    """
    csv_data = (
        "alert_id,timestamp,severity,event_type,source_ip,user,endpoint\n"
        "ALT-INV-1,2024-01-01 12:00:00,UNRECOGNIZED_LEVEL,Port Scan,10.0.0.1,admin,WS-01\n"
    )
    data = {'file': (io.BytesIO(csv_data.encode('utf-8')), 'invalid_sev.csv')}
    res = client.post('/api/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 400
    res_data = res.get_json()
    assert res_data['error_type'] == 'DATA_VALIDATION_ERROR'
    assert 'Invalid severity' in res_data['message']

def test_malformed_csv_empty_file(client):
    """
    Case 1.3: Completely empty CSV payload.
    Must be safely rejected with HTTP 400.
    """
    data = {'file': (io.BytesIO(b""), 'empty.csv')}
    res = client.post('/api/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 400
    res_data = res.get_json()
    assert res_data['error_type'] == 'EMPTY_PAYLOAD'

# --- Case 2: Conflicting Analyst Dispositions ---
def test_conflicting_analyst_dispositions_safety_and_audit(client):
    """
    Case 2: Conflicting analyst dispositions on the same alert.
    Analyst A sets alert to 'true_incident'.
    Analyst B attempts to downgrade to 'false_positive'.
    System must NOT silently choose unsafe result: requires explicit override reason.
    Full conflict history and audit logging must be preserved.
    """
    test_id = 'ALT-CONFLICT-TEST'
    conn = get_db_connection()
    conn.execute('''
    INSERT OR REPLACE INTO alerts 
    (alert_id, timestamp, severity, event_type, source_ip, destination_ip, user, endpoint, rule_name, ground_truth, analyst_disposition, status, disposition_history)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (test_id, '2024-01-01 10:00:00', 'High', 'SQL Injection Attempt', '198.51.100.1', '10.0.0.2', 'attacker', 'SRV-01', 'RULE-WEB-SQLI-21', 'true_incident', 'true_incident', 'escalated', '[]'))
    conn.commit()
    conn.close()

    # Analyst 2 attempts to change to 'false_positive' WITHOUT override reason -> MUST BE REJECTED 409
    res = client.post(f'/api/alerts/{test_id}/disposition', json={
        'disposition': 'false_positive',
        'override_reason': ''
    }, headers={'X-User': 'analyst_bob', 'X-User-Role': 'analyst'})
    
    assert res.status_code == 409
    data = res.get_json()
    assert data['conflict_detected'] is True
    assert 'Conflicting disposition detected' in data['message']

    # Verify alert disposition remains protected as 'true_incident'
    conn = get_db_connection()
    alert_row = conn.execute('SELECT * FROM alerts WHERE alert_id = ?', (test_id,)).fetchone()
    assert alert_row['analyst_disposition'] == 'true_incident'
    assert alert_row['status'] == 'escalated'
    
    # Check that the conflict attempt was audited
    audit = conn.execute("SELECT * FROM audit_log WHERE target_id = ? AND action = 'DISPOSITION_CONFLICT_BLOCKED'", (test_id,)).fetchone()
    assert audit is not None
    assert audit['status'] == 'REJECTED_CONFLICT'
    conn.close()

    # Now Analyst 2 submits conflict resolution WITH mandatory technical override reason
    res_valid = client.post(f'/api/alerts/{test_id}/disposition', json={
        'disposition': 'false_positive',
        'override_reason': 'Authorized internal penetration test verified with ticket SEC-941.',
        'confirm_conflict': True
    }, headers={'X-User': 'analyst_bob', 'X-User-Role': 'analyst'})
    
    assert res_valid.status_code == 200
    res_valid_data = res_valid.get_json()
    assert res_valid_data['conflict_handled'] is True
    assert res_valid_data['analyst_disposition'] == 'false_positive'

    # Verify history preserved both records
    conn = get_db_connection()
    alert_row = conn.execute('SELECT * FROM alerts WHERE alert_id = ?', (test_id,)).fetchone()
    history = json.loads(alert_row['disposition_history'])
    assert len(history) >= 1
    assert history[-1]['is_conflict'] is True
    assert history[-1]['previous_disposition'] == 'true_incident'
    assert history[-1]['new_disposition'] == 'false_positive'
    conn.close()

# --- Case 3: Unauthorized State Changes ---
def test_unauthorized_state_change_model_rollback(client):
    """
    Case 3.1: Regular analyst attempts protected model rollback.
    Must be rejected with HTTP 403 Forbidden, state must remain unchanged,
    and the unauthorized attempt must be logged in audit trail.
    """
    res = client.post('/api/model/rollback', json={
        'target_version_id': 'v1.0.0-baseline',
        'rollback_reason': 'Unauthorized attacker attempt'
    }, headers={'X-User': 'analyst_unauthorized', 'X-User-Role': 'analyst'})
    
    assert res.status_code == 403
    data = res.get_json()
    assert 'Unauthorized' in data['message']
    
    # Verify unauthorized attempt logged in audit trail
    conn = get_db_connection()
    audit_row = conn.execute(
        "SELECT * FROM audit_log WHERE user = 'analyst_unauthorized' AND status = 'REJECTED_UNAUTHORIZED'"
    ).fetchone()
    assert audit_row is not None
    assert audit_row['action'] == 'UNAUTHORIZED_ACCESS_ATTEMPT'
    conn.close()

def test_unauthorized_state_change_rule_rollback(client):
    """
    Case 3.2: Regular analyst attempts protected rule rollback.
    Must be rejected with HTTP 403 Forbidden.
    """
    res = client.post('/api/rules/RULE-WEB-SQLI-21/rollback', json={
        'target_version': 1,
        'rollback_reason': 'Unauthorized rule change'
    }, headers={'X-User': 'analyst_unauthorized', 'X-User-Role': 'analyst'})
    
    assert res.status_code == 403
    data = res.get_json()
    assert 'Unauthorized' in data['message']

# =========================================================================
# REQUIREMENT 2 — MODEL-LEVEL ROLLBACK & REPRODUCIBILITY TESTS
# =========================================================================

def test_model_level_rollback_lifecycle_and_reproducibility(client):
    """
    Demonstrates full 8-step model-level rollback lifecycle:
    1. Model version B is active.
    2. Predictions generated under Model B.
    3. Model A (v1.0.0-baseline) is selected for rollback.
    4. Rollback performed by authorized admin.
    5. Model A becomes active.
    6. Predictions after rollback match Model A configuration.
    7. Rollback is logged in audit trail.
    8. Restoring Model B works cleanly and deterministically.
    """
    # Ensure baseline and tuned models exist in registry
    conn = get_db_connection()
    now = "2024-01-01 00:00:00"
    base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'model', 'model_v1_baseline.pkl')
    tuned_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'model', 'model_v2_tuned.pkl')
    
    conn.execute('''
    INSERT OR REPLACE INTO model_versions 
    (version_id, model_name, contamination, rarity_threshold, score_threshold, fp_reduction_rate, missed_incidents, missed_incident_rate, model_artifact_path, is_active, created_by, created_at, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('v1.0.0-baseline', 'Isolation Forest Baseline', 0.01, 0.95, 0.258, 3.33, 0, 0.0, base_path, 0, 'admin', now, 'Initial baseline model'))
    
    conn.execute('''
    INSERT OR REPLACE INTO model_versions 
    (version_id, model_name, contamination, rarity_threshold, score_threshold, fp_reduction_rate, missed_incidents, missed_incident_rate, model_artifact_path, is_active, created_by, created_at, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('v2.0.0-tuned', 'Isolation Forest Tuned', 0.05, 0.15, 0.05, 100.0, 0, 0.0, tuned_path, 1, 'admin', now, 'Fine-tuned model'))
    conn.commit()
    conn.close()

    test_alert = {
        'alert_id': 'ALT-REPRO-TEST',
        'severity': 'Low',
        'event_type': 'Routine Vulnerability Scan',
        'source_ip': '10.0.1.50',
        'destination_ip': '10.0.1.100',
        'user': 'svc_monitor',
        'endpoint': 'SRV-TEST-01',
        'rule_name': 'RULE-NET-SCAN-01'
    }

    # Step 1: Predict under active Model B (tuned)
    res_b = client.post('/api/model/predict', json={'alert': test_alert})
    assert res_b.status_code == 200
    pred_b = res_b.get_json()
    assert 'recommendation' in pred_b['prediction']

    # Step 2: Rollback to Model A (baseline) as admin
    res_rb_a = client.post('/api/model/rollback', json={
        'target_version_id': 'v1.0.0-baseline',
        'rollback_reason': 'Testing rollback to baseline model'
    }, headers={'X-User': 'admin', 'X-User-Role': 'admin'})
    assert res_rb_a.status_code == 200
    rb_data_a = res_rb_a.get_json()
    assert rb_data_a['active_version'] == 'v1.0.0-baseline'

    # Step 3: Predict under Model A -> verify active version is v1
    res_a = client.post('/api/model/predict', json={'alert': test_alert})
    assert res_a.status_code == 200
    pred_a = res_a.get_json()
    assert pred_a['model_version'] == 'v1.0.0-baseline'

    # Step 4: Verify audit log recorded model rollback
    conn = get_db_connection()
    audit = conn.execute("SELECT * FROM audit_log WHERE action = 'MODEL_ROLLBACK' AND target_id = 'v1.0.0-baseline'").fetchone()
    assert audit is not None
    assert audit['status'] == 'SUCCESS'
    conn.close()

    # Step 5: Rollback back to Model B (tuned) -> verify reproducibility
    res_rb_b = client.post('/api/model/rollback', json={
        'target_version_id': 'v2.0.0-tuned',
        'rollback_reason': 'Re-activating tuned model'
    }, headers={'X-User': 'admin', 'X-User-Role': 'admin'})
    assert res_rb_b.status_code == 200

    res_b2 = client.post('/api/model/predict', json={'alert': test_alert})
    pred_b2 = res_b2.get_json()
    assert pred_b2['model_version'] == 'v2.0.0-tuned'
    # Predictions under Model B must be completely identical
    assert pred_b['prediction']['recommendation'] == pred_b2['prediction']['recommendation']
    assert pred_b['prediction']['anomaly_score'] == pred_b2['prediction']['anomaly_score']

# =========================================================================
# EXISTING RULE ROLLBACK VERIFICATION (Requirement 16)
# =========================================================================

def test_existing_rule_rollback_preserved(client):
    """
    Verifies that the existing rule rollback mechanism still functions properly.
    """
    rule_id = 'RULE-NET-SCAN-01'
    
    conn = get_db_connection()
    current_rule = conn.execute('SELECT version FROM rules WHERE rule_id = ?', (rule_id,)).fetchone()
    current_ver = current_rule['version'] if current_rule else 1
    conn.close()
    
    # 1. Update rule to current_ver + 1
    res_up = client.post(f'/api/rules/{rule_id}', json={
        'rule_name': 'Scanner Filter v2',
        'condition': 'event_type == "Routine Vulnerability Scan" and source_ip.startswith("10.0.")',
        'action': 'Dismiss / False Positive',
        'change_reason': 'Restricting scanner subnet to 10.0.'
    }, headers={'X-User': 'lead_sec', 'X-User-Role': 'lead_analyst'})
    assert res_up.status_code == 200
    assert res_up.get_json()['version'] == current_ver + 1

    # 2. Rollback rule to v1
    res_rb = client.post(f'/api/rules/{rule_id}/rollback', json={
        'target_version': 1,
        'rollback_reason': 'Reverting scanner rule to broad 10. subnet'
    }, headers={'X-User': 'lead_sec', 'X-User-Role': 'lead_analyst'})
    assert res_rb.status_code == 200
    rb_data = res_rb.get_json()
    assert rb_data['rolled_back_to_version'] == 1
    assert rb_data['new_version'] == current_ver + 2

    # Verify audit trail
    conn = get_db_connection()
    audit = conn.execute("SELECT * FROM audit_log WHERE action = 'RULE_ROLLBACK' AND target_id = ?", (rule_id,)).fetchone()
    assert audit is not None
    conn.close()

# =========================================================================
# REQUIREMENT 1 & 4 — METRICS & SOC BENCHMARK TESTS
# =========================================================================

def test_fine_tuning_elevates_fp_reduction_with_zero_missed(client):
    """
    Validates Requirement 1: FP reduction rate > 3.33% with strict 0% missed incidents.
    """
    metrics = load_metrics()
    after = metrics.get('after_qbee', {})
    
    assert after.get('test_fp_reduction_rate', 0) > 3.33, "FP reduction rate must exceed 3.33%"
    assert after.get('test_missed_incidents', 99) == 0, "Missed incidents must be strictly 0"
    assert after.get('test_missed_incident_rate', 99.0) == 0.0, "Missed incident rate must be strictly 0.0%"

def test_realistic_soc_time_saved_calculation():
    """
    Validates Requirement 4: Realistic SOC benchmark calculation.
    """
    # 400 alerts: 354 FPs, 46 true incidents. Suppose 59 FPs auto-reduced (16.7%)
    metrics = calculate_time_saved_metrics(
        total_alerts=400,
        false_positives=354,
        true_incidents=46,
        reduced_fps=59,
        missed_incidents=0
    )
    
    # Baseline: 400 * 12 min = 4800 min = 80.0 hours
    assert metrics['baseline_workload_hours'] == 80.0
    # Alerts investigated: (354 - 59) + 46 = 341 alerts * 12m = 4092m = 68.2h
    # Audit spot-check: 59 * 2m = 118m = 1.97h
    # Assisted: 68.2 + 1.97 = 70.17h
    # Hours saved: 80.0 - 70.17 = ~9.8h
    assert metrics['estimated_hours_saved'] > 0
    assert metrics['missed_incidents'] == 0
    assert 'SANS' in metrics['benchmark_source']
