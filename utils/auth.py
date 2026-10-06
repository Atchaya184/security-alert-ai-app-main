from functools import wraps
from flask import request, jsonify, session
from utils.audit_csv import log_audit_event
from utils.db import get_db_connection

# Role-Based Access Control (RBAC) Permission Matrix
# Role hierarchy: admin (Super-user) > lead_analyst (Senior/Lead) > analyst (Tier 1/2 SOC)
# Principle of Least Privilege:
# - 'admin': Full operational control including model-level rollback and system administration.
# - 'lead_analyst': Detection engineering permissions (rule updates, rule rollback, overrides).
# - 'analyst': Standard operational alert triage, disposition tagging, and audit log inspection.
ROLE_PERMISSIONS = {
    'admin': [
        'view_alerts', 'disposition_alert', 'override_alert',
        'manage_rules', 'rollback_rules', 'retrain_model',
        'rollback_model', 'view_audit', 'upload_csv'
    ],
    'lead_analyst': [
        'view_alerts', 'disposition_alert', 'override_alert',
        'manage_rules', 'rollback_rules', 'view_audit', 'upload_csv'
    ],
    'analyst': [
        'view_alerts', 'disposition_alert', 'view_audit'
    ]
}

def authenticate_user(username, password):
    """Verifies credentials against the SQLite users table."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password)).fetchone()
    conn.close()
    if user:
        return {'username': user['username'], 'role': user['role']}
    return None

def get_current_user():
    """
    Resolves client identity using dual-mode mechanism:
    1. HTTP Headers ('X-User', 'X-User-Role') for REST API clients and automated tests.
    2. Flask session store for interactive Web UI analyst sessions.
    3. Safe default fallback to analyst_jdoe (role: analyst) for development.
    """
    auth_header = request.headers.get('X-User-Role')
    user_header = request.headers.get('X-User', 'analyst_jdoe')
    if auth_header:
        return {'username': user_header, 'role': auth_header}
    
    if 'user' in session:
        return session['user']
        
    # Default to standard analyst (role: analyst) if no session exists
    return {'username': 'analyst_jdoe', 'role': 'analyst'}

def require_permission(permission):
    """
    Decorator enforcing endpoint authorization boundaries.
    
    Security Contract:
    - If caller role possesses required permission -> proceed to wrapped function.
    - If caller lacks permission ->
      1. Log an immutable UNAUTHORIZED_ACCESS_ATTEMPT record in both SQLite and audit_log.csv.
      2. Immediately abort request with HTTP 403 Forbidden structured JSON error.
      3. Guaranteed zero state mutation on unauthorized access attempts.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            user_role = user.get('role', 'analyst')
            allowed_permissions = ROLE_PERMISSIONS.get(user_role, [])
            
            if permission not in allowed_permissions:
                # Log unauthorized state change attempt to audit trail!
                log_audit_event(
                    user=user.get('username', 'anonymous'),
                    action='UNAUTHORIZED_ACCESS_ATTEMPT',
                    target_type='permission_check',
                    target_id=permission,
                    details=f"User with role '{user_role}' attempted protected action requiring permission '{permission}'.",
                    status='REJECTED_UNAUTHORIZED'
                )
                return jsonify({
                    'status': 'error',
                    'message': f"Unauthorized: Role '{user_role}' lacks required permission '{permission}'.",
                    'code': 403
                }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
