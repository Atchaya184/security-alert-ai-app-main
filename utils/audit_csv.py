import csv
import os
from datetime import datetime
from utils.db import get_db_connection

# Path to the immutable append-only CSV audit log file
AUDIT_CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'audit_log.csv')

def log_audit_event(user, action, target_type, target_id, details, status='SUCCESS'):
    """
    Dual-Logging Compliance Pattern:
    Simultaneously records all security-relevant operational actions to both:
    1. SQLite relational database (`audit_log` table) for fast indexed querying and UI presentation.
    2. Flat CSV file (`audit_log.csv`) for immutable export, SIEM ingestion, and cold-storage compliance.
    
    Non-Repudiation Contract:
    - Every disposition change, manual override, rule edit, rule rollback, model rollback,
      CSV ingestion, conflict detection, and unauthorized attempt is recorded with:
      * UTC timestamp
      * Acting analyst username
      * Action taxonomy type
      * Target entity reference (alert_id, rule_id, version_id)
      * Technical justification / details
      * Status outcome (SUCCESS, REJECTED_CONFLICT, REJECTED_UNAUTHORIZED, ERROR)
    """
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    
    # 1. Primary Relational Persistence (SQLite)
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO audit_log (timestamp, user, action, target_type, target_id, details, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (now, user, action, target_type, str(target_id), str(details), status)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        # Error containment: Database failure must not crash active request, but prints diagnostic
        print(f"Error logging to DB audit log: {e}")
        
    # 2. Secondary Flat-File Persistence (audit_log.csv)
    file_exists = os.path.exists(AUDIT_CSV_PATH)
    try:
        with open(AUDIT_CSV_PATH, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['timestamp', 'user', 'action', 'target_type', 'target_id', 'details', 'status'])
            writer.writerow([now, user, action, target_type, str(target_id), str(details), status])
    except Exception as e:
        print(f"Error appending to audit_log.csv: {e}")
