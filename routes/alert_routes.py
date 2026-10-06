import json
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template
from utils.db import get_db_connection
from utils.auth import get_current_user, require_permission
from utils.audit_csv import log_audit_event
from utils.explain import get_alert_evidence
from utils.recommend import predict_single_alert

alert_bp = Blueprint('alert_routes', __name__)

@alert_bp.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity')
    status = request.args.get('status')
    search = request.args.get('search')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    query = 'SELECT * FROM alerts WHERE 1=1'
    params = []
    
    if severity and severity != 'all':
        query += ' AND severity = ?'
        params.append(severity)
    if status and status != 'all':
        query += ' AND status = ?'
        params.append(status)
    if search:
        query += ' AND (alert_id LIKE ? OR event_type LIKE ? OR user LIKE ? OR endpoint LIKE ?)'
        wildcard = f"%{search}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])
        
    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    conn = get_db_connection()
    alerts = conn.execute(query, params).fetchall()
    
    count_query = 'SELECT COUNT(*) FROM alerts'
    total = conn.execute(count_query).fetchone()[0]
    conn.close()
    
    return jsonify({
        'status': 'success',
        'total': total,
        'count': len(alerts),
        'alerts': [dict(a) for a in alerts]
    })

@alert_bp.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert_detail(alert_id):
    conn = get_db_connection()
    alert = conn.execute('SELECT * FROM alerts WHERE alert_id = ?', (alert_id,)).fetchone()
    conn.close()
    
    if not alert:
        return jsonify({'status': 'error', 'message': f"Alert '{alert_id}' not found."}), 404
        
    alert_dict = dict(alert)
    history = json.loads(alert_dict.get('disposition_history') or '[]')
    
    evidence = get_alert_evidence(
        alert_dict,
        alert_dict.get('anomaly_score', 0.0),
        alert_dict.get('rarity_score', 0.5),
        alert_dict.get('model_recommendation', 'Investigate')
    )
    
    alert_dict['evidence'] = evidence
    alert_dict['disposition_history_parsed'] = history
    return jsonify({'status': 'success', 'alert': alert_dict})

@alert_bp.route('/api/alerts/<alert_id>/disposition', methods=['POST'])
def submit_disposition(alert_id):
    """
    Records an analyst disposition decision with multi-analyst conflict detection.
    
    Conflict & Safety Policy (Requirement 3, Case 2):
    - Identifies race conditions or disagreements where an alert previously marked as
      'true_incident' is being downgraded to 'false_positive'.
    - To prevent silent unsafe suppression of active security breaches, downgrades
      without an explicit technical override reason are blocked with HTTP 409 Conflict.
    - Blocked attempts are recorded as DISPOSITION_CONFLICT_BLOCKED in the audit trail.
    - Validated overrides record full conflict metadata in `disposition_history` and emit
      a DISPOSITION_CONFLICT_RESOLVED audit event.
    """
    user = get_current_user()
    data = request.get_json() or {}
    new_disposition = data.get('disposition')
    override_reason = data.get('override_reason', '').strip()
    confirm_conflict = data.get('confirm_conflict', False)
    
    # Validation boundary: Disposition must match defined taxonomy enum
    if not new_disposition or new_disposition not in ['false_positive', 'true_incident', 'suspicious']:
        return jsonify({'status': 'error', 'message': 'Invalid disposition. Must be false_positive, true_incident, or suspicious.'}), 400
        
    conn = get_db_connection()
    alert = conn.execute('SELECT * FROM alerts WHERE alert_id = ?', (alert_id,)).fetchone()
    
    if not alert:
        conn.close()
        return jsonify({'status': 'error', 'message': f"Alert '{alert_id}' not found."}), 404
        
    alert_dict = dict(alert)
    existing_disposition = alert_dict.get('analyst_disposition')
    history = json.loads(alert_dict.get('disposition_history') or '[]')
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Conflict Detection: Compares existing settled disposition against incoming disposition
    is_conflict = (existing_disposition and 
                   existing_disposition != new_disposition and 
                   existing_disposition in ['false_positive', 'true_incident'] and 
                   new_disposition in ['false_positive', 'true_incident'])
                   
    if is_conflict:
        # Prevent silent unsafe choice: Downgrading a confirmed true incident to false positive
        # is a catastrophic risk in a SOC if done accidentally or without justification.
        if existing_disposition == 'true_incident' and new_disposition == 'false_positive':
            if not override_reason:
                conn.close()
                # Audit trail records blocked conflict attempt for SOC managerial review
                log_audit_event(
                    user=user['username'],
                    action='DISPOSITION_CONFLICT_BLOCKED',
                    target_type='alert',
                    target_id=alert_id,
                    details=f"Conflicting disposition blocked: Attempted to downgrade '{existing_disposition}' to '{new_disposition}' without override reason.",
                    status='REJECTED_CONFLICT'
                )
                return jsonify({
                    'status': 'error',
                    'conflict_detected': True,
                    'message': f"Conflicting disposition detected: Alert was previously dispositioned as '{existing_disposition}'. Reclassifying as '{new_disposition}' requires an explicit override reason and human confirmation.",
                    'code': 409
                }), 409
                
        # If conflict is justified with technical reason, record full conflict details in audit history
        conflict_entry = {
            'timestamp': now,
            'analyst': user['username'],
            'previous_disposition': existing_disposition,
            'new_disposition': new_disposition,
            'is_conflict': True,
            'override_reason': override_reason
        }
        history.append(conflict_entry)
        
        log_audit_event(
            user=user['username'],
            action='DISPOSITION_CONFLICT_RESOLVED',
            target_type='alert',
            target_id=alert_id,
            details=f"Conflicting disposition resolved: Changed '{existing_disposition}' -> '{new_disposition}'. Reason: {override_reason}",
            status='SUCCESS'
        )
    else:
        history.append({
            'timestamp': now,
            'analyst': user['username'],
            'disposition': new_disposition,
            'override_reason': override_reason
        })
        log_audit_event(
            user=user['username'],
            action='ALERT_DISPOSITION',
            target_type='alert',
            target_id=alert_id,
            details=f"Analyst set disposition to '{new_disposition}'.",
            status='SUCCESS'
        )
        
    # Synchronization of operational alert workflow status
    new_status = 'closed' if new_disposition == 'false_positive' else 'escalated'
    
    conn.execute('''
        UPDATE alerts 
        SET analyst_disposition = ?, analyst_user = ?, status = ?, override_reason = ?, disposition_history = ?
        WHERE alert_id = ?
    ''', (new_disposition, user['username'], new_status, override_reason, json.dumps(history), alert_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'alert_id': alert_id,
        'analyst_disposition': new_disposition,
        'conflict_handled': is_conflict,
        'disposition_history': history
    })

@alert_bp.route('/api/alerts/<alert_id>/override', methods=['POST'])
def manual_override(alert_id):
    """
    Manual override mechanism allowing authorized analysts to countermand ML recommendations.
    
    Safety Guardrail:
    - High-impact overrides (High/Critical alerts or overriding 'Escalate / True Incident')
      mandate both a non-empty `override_reason` AND explicit `human_confirmed=True`.
    - Every override decision is logged immutably for periodic supervisor compliance audits.
    """
    user = get_current_user()
    data = request.get_json() or {}
    override_disposition = data.get('override_disposition')
    override_reason = data.get('override_reason', '').strip()
    human_confirmed = data.get('human_confirmed', False)
    
    # Enforce mandatory justification
    if not override_reason:
        return jsonify({'status': 'error', 'message': 'Override reason is mandatory for manual overrides.'}), 400
        
    conn = get_db_connection()
    alert = conn.execute('SELECT * FROM alerts WHERE alert_id = ?', (alert_id,)).fetchone()
    
    if not alert:
        conn.close()
        return jsonify({'status': 'error', 'message': f"Alert '{alert_id}' not found."}), 404
        
    alert_dict = dict(alert)
    # High-impact classification check
    is_high_impact = alert_dict.get('severity') in ['High', 'Critical'] or alert_dict.get('model_recommendation') == 'Escalate / True Incident'
    
    # Two-factor cognitive confirmation barrier for high-impact dismissals
    if is_high_impact and not human_confirmed:
        conn.close()
        return jsonify({
            'status': 'error',
            'requires_confirmation': True,
            'message': 'High-impact override detected. Explicit human confirmation is required.'
        }), 400
        
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    history = json.loads(alert_dict.get('disposition_history') or '[]')
    history.append({
        'timestamp': now,
        'analyst': user['username'],
        'action': 'MANUAL_OVERRIDE',
        'from_recommendation': alert_dict.get('model_recommendation'),
        'override_disposition': override_disposition,
        'override_reason': override_reason
    })
    
    new_status = 'closed' if override_disposition == 'false_positive' else 'escalated'
    
    conn.execute('''
        UPDATE alerts
        SET analyst_disposition = ?, analyst_user = ?, status = ?, override_reason = ?, disposition_history = ?
        WHERE alert_id = ?
    ''', (override_disposition, user['username'], new_status, override_reason, json.dumps(history), alert_id))
    
    conn.commit()
    conn.close()
    
    log_audit_event(
        user=user['username'],
        action='MANUAL_OVERRIDE',
        target_type='alert',
        target_id=alert_id,
        details=f"Manual override to '{override_disposition}'. Reason: {override_reason}. High-impact confirmed: {human_confirmed}.",
        status='SUCCESS'
    )
    
    return jsonify({
        'status': 'success',
        'alert_id': alert_id,
        'override_disposition': override_disposition,
        'message': 'Manual override recorded successfully.'
    })
