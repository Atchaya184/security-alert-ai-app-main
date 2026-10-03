from functools import wraps
from flask import request, jsonify, session
from utils.audit_csv import log_audit_event
from utils.db import get_db_connection

# Role hierarchy: admin > lead_analyst > analyst
ROLE_PERMISSIONS = {
    'admin': ['view_alerts', 'disposition_alert', 'override_alert', 'manage_rules', 'rollback_rules', 'retrain_model', 'rollback_model', 'view_audit', 'upload_csv'],
    'lead_analyst': ['view_alerts', 'disposition_alert', 'override_alert', 'manage_rules', 'rollback_rules', 'view_audit', 'upload_csv'],
    'analyst': ['view_alerts', 'disposition_alert', 'view_audit']
}

def authenticate_user(username, password):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?', (username, password)).fetchone()
    conn.close()
    if user:
        return {'username': user['username'], 'role': user['role']}
    return None

def get_current_user():
    # Supports session user or Authorization / X-User header for API & automated tests
    auth_header = request.headers.get('X-User-Role')
    user_header = request.headers.get('X-User', 'analyst_jdoe')
    if auth_header:
        return {'username': user_header, 'role': auth_header}
    
    if 'user' in session:
        return session['user']
        
    # Default to analyst_jdoe (role: analyst) for web UI convenience if no session
    return {'username': 'analyst_jdoe', 'role': 'analyst'}

def require_permission(permission):
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
