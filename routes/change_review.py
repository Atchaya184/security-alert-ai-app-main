import json
from datetime import datetime
from flask import Blueprint, request, jsonify
from utils.db import get_db_connection
from utils.auth import get_current_user, require_permission
from utils.audit_csv import log_audit_event

change_bp = Blueprint('change_review', __name__)

@change_bp.route('/api/rules', methods=['GET'])
def get_rules():
    conn = get_db_connection()
    rules = conn.execute('SELECT * FROM rules ORDER BY rule_id ASC').fetchall()
    conn.close()
    return jsonify({
        'status': 'success',
        'rules': [dict(r) for r in rules]
    })

@change_bp.route('/api/rules/<rule_id>/history', methods=['GET'])
def get_rule_history(rule_id):
    conn = get_db_connection()
    history = conn.execute(
        'SELECT * FROM rule_history WHERE rule_id = ? ORDER BY version DESC',
        (rule_id,)
    ).fetchall()
    conn.close()
    return jsonify({
        'status': 'success',
        'rule_id': rule_id,
        'history': [dict(h) for h in history]
    })

@change_bp.route('/api/rules/<rule_id>', methods=['POST'])
@require_permission('manage_rules')
def update_rule(rule_id):
    """
    Modifies or creates a detection rule with mandatory change justification.
    
    Versioning Policy:
    - Increments rule version monotonically (v1 -> v2 -> v3).
    - Preserves a complete historical snapshot in `rule_history` with author,
      timestamp, and change reason.
    - Requires 'manage_rules' RBAC permission (lead_analyst or admin).
    """
    user = get_current_user()
    data = request.get_json() or {}
    
    rule_name = data.get('rule_name')
    condition = data.get('condition')
    action = data.get('action')
    change_reason = data.get('change_reason', '').strip()
    
    # Validation boundary: Reject modification without technical change justification
    if not change_reason:
        return jsonify({
            'status': 'error',
            'message': 'Change reason is mandatory for rule modifications.'
        }), 400
        
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM rules WHERE rule_id = ?', (rule_id,)).fetchone()
    
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    if existing:
        new_version = existing['version'] + 1
        conn.execute('''
            UPDATE rules 
            SET rule_name = ?, condition = ?, action = ?, version = ?, created_by = ?, created_at = ?
            WHERE rule_id = ?
        ''', (
            rule_name or existing['rule_name'],
            condition or existing['condition'],
            action or existing['action'],
            new_version,
            user['username'],
            now,
            rule_id
        ))
    else:
        new_version = 1
        conn.execute('''
            INSERT INTO rules (rule_id, rule_name, severity, description, condition, action, version, is_active, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule_id,
            rule_name or rule_id,
            data.get('severity', 'Medium'),
            data.get('description', ''),
            condition or 'True',
            action or 'Investigate',
            new_version,
            1,
            user['username'],
            now
        ))
        
    # Append immutable historical snapshot to rule_history table
    conn.execute('''
        INSERT INTO rule_history (rule_id, version, rule_name, condition, action, changed_by, changed_at, change_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        rule_id,
        new_version,
        rule_name or rule_id,
        condition or 'True',
        action or 'Investigate',
        user['username'],
        now,
        change_reason
    ))
    
    conn.commit()
    conn.close()
    
    log_audit_event(
        user=user['username'],
        action='RULE_UPDATE',
        target_type='rule',
        target_id=rule_id,
        details=f"Updated rule to v{new_version}. Reason: {change_reason}",
        status='SUCCESS'
    )
    
    return jsonify({
        'status': 'success',
        'rule_id': rule_id,
        'version': new_version,
        'message': f"Rule '{rule_id}' updated to version {new_version}."
    })

@change_bp.route('/api/rules/<rule_id>/rollback', methods=['POST'])
@require_permission('rollback_rules')
def rollback_rule(rule_id):
    """
    Rolls back detection rule to a previous version from rule_history.
    
    Non-Destructive Rollback Semantics:
    Rather than rewinding or deleting history records, the target historical state
    is applied as a brand-new incremented version (e.g. rolling back v2 to v1 produces v3).
    This guarantees monotonic version tracking, eliminates historical ambiguity, and ensures
    that audit logs reflect the exact linear progression of all rule configurations.
    """
    user = get_current_user()
    data = request.get_json() or {}
    target_version = data.get('target_version')
    rollback_reason = data.get('rollback_reason', '').strip()
    
    if not target_version:
        return jsonify({'status': 'error', 'message': 'target_version is required for rollback.'}), 400
    if not rollback_reason:
        return jsonify({'status': 'error', 'message': 'rollback_reason is required for rule rollback.'}), 400
        
    conn = get_db_connection()
    target_hist = conn.execute(
        'SELECT * FROM rule_history WHERE rule_id = ? AND version = ?',
        (rule_id, target_version)
    ).fetchone()
    
    if not target_hist:
        conn.close()
        return jsonify({
            'status': 'error',
            'message': f"Version {target_version} not found in history for rule '{rule_id}'."
        }), 404
        
    current_rule = conn.execute('SELECT * FROM rules WHERE rule_id = ?', (rule_id,)).fetchone()
    current_ver = current_rule['version'] if current_rule else 0
    # Linear version increment preserves append-only integrity
    new_version = current_ver + 1
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Update active rule with historical content and increment version
    conn.execute('''
        UPDATE rules
        SET rule_name = ?, condition = ?, action = ?, version = ?, created_by = ?, created_at = ?
        WHERE rule_id = ?
    ''', (
        target_hist['rule_name'],
        target_hist['condition'],
        target_hist['action'],
        new_version,
        user['username'],
        now,
        rule_id
    ))
    
    # Record rollback in history
    conn.execute('''
        INSERT INTO rule_history (rule_id, version, rule_name, condition, action, changed_by, changed_at, change_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        rule_id,
        new_version,
        target_hist['rule_name'],
        target_hist['condition'],
        target_hist['action'],
        user['username'],
        now,
        f"Rollback to v{target_version}. Reason: {rollback_reason}"
    ))
    
    conn.commit()
    conn.close()
    
    log_audit_event(
        user=user['username'],
        action='RULE_ROLLBACK',
        target_type='rule',
        target_id=rule_id,
        details=f"Rolled back rule '{rule_id}' to content of v{target_version} (as new v{new_version}). Reason: {rollback_reason}",
        status='SUCCESS'
    )
    
    return jsonify({
        'status': 'success',
        'rule_id': rule_id,
        'rolled_back_to_version': target_version,
        'new_version': new_version,
        'message': f"Rule '{rule_id}' successfully rolled back to version {target_version}."
    })
