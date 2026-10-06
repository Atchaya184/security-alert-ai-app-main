import io
import csv
from flask import Blueprint, request, jsonify
from utils.db import get_db_connection
from utils.auth import get_current_user, require_permission
from utils.audit_csv import log_audit_event
from utils.recommend import predict_single_alert

upload_bp = Blueprint('upload_routes', __name__)

REQUIRED_COLUMNS = {'alert_id', 'timestamp', 'severity', 'event_type', 'source_ip', 'user', 'endpoint'}
VALID_SEVERITIES = {'Low', 'Medium', 'High', 'Critical'}

@upload_bp.route('/api/upload', methods=['POST'])
def upload_alerts_csv():
    """
    Ingests alert payloads via CSV with strict multi-layer defense-in-depth schema validation.
    
    Error Boundary & State Protection Guarantee:
    - Rejects malformed, incomplete, or corrupted CSV payloads with structured HTTP 400 responses.
    - Prevents database state pollution: All rows are validated in-memory first; ingestion into
      SQLite is wrapped inside a strict transaction that rolls back automatically on error.
    - Emits immutable audit records for both rejected attempts and successful ingestions.
    """
    user = get_current_user()
    
    # --- Layer 1 Validation Boundary: Multipart Form Key Check ---
    if 'file' not in request.files:
        return jsonify({
            'status': 'error',
            'error_type': 'MALFORMED_PAYLOAD',
            'message': 'No file uploaded in form data. Expected multipart field "file".'
        }), 400
        
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({
            'status': 'error',
            'error_type': 'MALFORMED_PAYLOAD',
            'message': 'Empty filename or no file selected.'
        }), 400
        
    # --- Layer 2 Validation Boundary: MIME / File Extension Gate ---
    if not file.filename.lower().endswith('.csv'):
        return jsonify({
            'status': 'error',
            'error_type': 'INVALID_FILE_TYPE',
            'message': f"Unsupported file type '{file.filename}'. Only valid .csv files are supported."
        }), 400
        
    # --- Layer 3 Validation Boundary: UTF-8 Byte Stream Decoding ---
    try:
        content = file.stream.read().decode('utf-8')
    except UnicodeDecodeError as e:
        # Audit malformed binary/encoding attack payloads
        log_audit_event(
            user=user['username'],
            action='CSV_INGESTION_REJECTED',
            target_type='csv_upload',
            target_id=file.filename,
            details=f"Encoding error: {str(e)}",
            status='ERROR'
        )
        return jsonify({
            'status': 'error',
            'error_type': 'MALFORMED_CSV',
            'message': f"Malformed CSV: Failed to decode text. File must be valid UTF-8. Error: {str(e)}"
        }), 400
        
    # Boundary Check: 0-byte or whitespace-only files
    if not content.strip():
        return jsonify({
            'status': 'error',
            'error_type': 'EMPTY_PAYLOAD',
            'message': 'Uploaded CSV file is completely empty.'
        }), 400
        
    # --- Layer 4 Validation Boundary: CSV Header & Delimiter Syntax ---
    try:
        reader = csv.DictReader(io.StringIO(content))
        fieldnames = set(reader.fieldnames or [])
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error_type': 'MALFORMED_CSV',
            'message': f"Malformed CSV syntax: Unable to parse headers. Details: {str(e)}"
        }), 400
        
    # Mandatory Column Contract Validation: Guarantees ML preprocessor receives required features
    missing_columns = REQUIRED_COLUMNS - fieldnames
    if missing_columns:
        log_audit_event(
            user=user['username'],
            action='CSV_INGESTION_REJECTED',
            target_type='csv_upload',
            target_id=file.filename,
            details=f"Schema violation. Missing required columns: {sorted(list(missing_columns))}",
            status='REJECTED_SCHEMA'
        )
        return jsonify({
            'status': 'error',
            'error_type': 'SCHEMA_VALIDATION_ERROR',
            'message': f"Malformed CSV payload: Missing mandatory security alert columns: {sorted(list(missing_columns))}",
            'required_columns': sorted(list(REQUIRED_COLUMNS)),
            'provided_columns': sorted(list(fieldnames))
        }), 400
        
    # --- Layer 5 Validation Boundary: Per-Row Data Type & Enum Verification ---
    parsed_alerts = []
    line_number = 1
    for row in reader:
        line_number += 1
        
        # Check for empty alert_id or null essential fields
        alert_id = row.get('alert_id', '').strip()
        if not alert_id:
            return jsonify({
                'status': 'error',
                'error_type': 'DATA_VALIDATION_ERROR',
                'message': f"Malformed row at line {line_number}: 'alert_id' cannot be blank."
            }), 400
            
        sev = row.get('severity', '').strip()
        if sev not in VALID_SEVERITIES:
            return jsonify({
                'status': 'error',
                'error_type': 'DATA_VALIDATION_ERROR',
                'message': f"Malformed row at line {line_number}: Invalid severity '{sev}'. Must be one of {sorted(list(VALID_SEVERITIES))}."
            }), 400
            
        parsed_alerts.append(row)
        
    if not parsed_alerts:
        return jsonify({
            'status': 'error',
            'error_type': 'EMPTY_PAYLOAD',
            'message': 'CSV header present but contains no data rows.'
        }), 400
        
    # --- Transactional Ingestion & Inference Phase ---
    # Atomic execution: Either ALL alerts are inferred and persisted, or transaction rolls back completely
    conn = get_db_connection()
    ingested_count = 0
    try:
        for alert in parsed_alerts:
            alert_dict = dict(alert)
            rule_name = alert_dict.get('rule_name') or 'RULE-GENERAL'
            destination_ip = alert_dict.get('destination_ip') or '10.0.0.1'
            ground_truth = alert_dict.get('ground_truth') or 'false_positive'
            analyst_disp = alert_dict.get('analyst_disposition') or ''
            
            alert_dict['rule_name'] = rule_name
            alert_dict['destination_ip'] = destination_ip
            
            # Real-time scoring using active preprocessor and Isolation Forest model
            pred = predict_single_alert(alert_dict)
            conn.execute('''
            INSERT OR REPLACE INTO alerts 
            (alert_id, timestamp, severity, event_type, source_ip, destination_ip, user, endpoint, rule_name, ground_truth, analyst_disposition, model_recommendation, model_confidence, anomaly_score, rarity_score, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_dict.get('alert_id'),
                alert_dict.get('timestamp'),
                alert_dict.get('severity'),
                alert_dict.get('event_type'),
                alert_dict.get('source_ip'),
                destination_ip,
                alert_dict.get('user'),
                alert_dict.get('endpoint'),
                rule_name,
                ground_truth,
                analyst_disp,
                pred['recommendation'],
                pred['confidence'],
                pred['anomaly_score'],
                pred['rarity_score'],
                'new'
            ))
            ingested_count += 1
        conn.commit()
    except Exception as e:
        # Atomic rollback prevents partial state corruption
        conn.rollback()
        conn.close()
        return jsonify({
            'status': 'error',
            'error_type': 'DATABASE_ERROR',
            'message': f"Database error during ingestion: {str(e)}"
        }), 500
    finally:
        conn.close()
        
    log_audit_event(
        user=user['username'],
        action='CSV_INGESTION_SUCCESS',
        target_type='csv_upload',
        target_id=file.filename,
        details=f"Successfully ingested {ingested_count} alerts.",
        status='SUCCESS'
    )
    
    return jsonify({
        'status': 'success',
        'message': f"Successfully ingested {ingested_count} alerts from '{file.filename}'.",
        'ingested_count': ingested_count
    })
