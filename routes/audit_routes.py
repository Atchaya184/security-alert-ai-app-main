from flask import Blueprint, request, jsonify
from utils.db import get_db_connection
from utils.auth import get_current_user, require_permission

audit_bp = Blueprint('audit_routes', __name__)

@audit_bp.route('/api/audit', methods=['GET'])
def get_audit_logs():
    user_filter = request.args.get('user')
    action_filter = request.args.get('action')
    status_filter = request.args.get('status')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    query = 'SELECT * FROM audit_log WHERE 1=1'
    params = []
    
    if user_filter:
        query += ' AND user = ?'
        params.append(user_filter)
    if action_filter:
        query += ' AND action = ?'
        params.append(action_filter)
    if status_filter:
        query += ' AND status = ?'
        params.append(status_filter)
        
    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    conn = get_db_connection()
    logs = conn.execute(query, params).fetchall()
    total = conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
    conn.close()
    
    return jsonify({
        'status': 'success',
        'total': total,
        'count': len(logs),
        'logs': [dict(l) for l in logs]
    })
