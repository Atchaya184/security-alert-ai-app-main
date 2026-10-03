import csv
import os
from datetime import datetime
from utils.db import get_db_connection

AUDIT_CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'audit_log.csv')

def log_audit_event(user, action, target_type, target_id, details, status='SUCCESS'):
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    
    # 1. Log to SQLite
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO audit_log (timestamp, user, action, target_type, target_id, details, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (now, user, action, target_type, str(target_id), str(details), status)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging to DB audit log: {e}")
        
    # 2. Append to audit_log.csv
    file_exists = os.path.exists(AUDIT_CSV_PATH)
    try:
        with open(AUDIT_CSV_PATH, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['timestamp', 'user', 'action', 'target_type', 'target_id', 'details', 'status'])
            writer.writerow([now, user, action, target_type, str(target_id), str(details), status])
    except Exception as e:
        print(f"Error appending to audit_log.csv: {e}")
