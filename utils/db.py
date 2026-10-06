import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes SQLite relational schema for security alert triage governance.
    
    Persistence Architecture:
    - Tables: alerts, rules, rule_history, model_versions, audit_log, users.
    - Preserves audit trails, model version registries, and historical rollback states.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Alerts Table: Core operational table storing raw telemetry, ML inference outputs, and analyst state
    # Keys/Constraints: PRIMARY KEY (alert_id)
    # Versioning/Audit: disposition_history (JSON array of all analyst actions and conflict resolutions)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        severity TEXT NOT NULL,
        event_type TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        user TEXT,
        endpoint TEXT,
        rule_name TEXT,
        ground_truth TEXT,
        analyst_disposition TEXT,
        analyst_user TEXT,
        model_recommendation TEXT,
        model_confidence REAL,
        anomaly_score REAL,
        rarity_score REAL,
        status TEXT DEFAULT 'new',
        override_reason TEXT,
        disposition_history TEXT DEFAULT '[]'
    )
    ''')
    
    # 2. Rules Table: Active detection rules evaluated against alerts
    # Keys/Constraints: PRIMARY KEY (rule_id)
    # Versioning/Audit: version (monotonically increasing integer), created_by, created_at
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS rules (
        rule_id TEXT PRIMARY KEY,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT,
        condition TEXT NOT NULL,
        action TEXT NOT NULL,
        version INTEGER DEFAULT 1,
        is_active INTEGER DEFAULT 1,
        created_by TEXT DEFAULT 'system',
        created_at TEXT NOT NULL
    )
    ''')
    
    # 3. Rule History Table: Immutable append-only audit snapshot of rule modifications
    # Keys/Constraints: PRIMARY KEY (history_id AUTOINCREMENT), Foreign Reference (rule_id)
    # Versioning/Audit: version, changed_by, changed_at, change_reason
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS rule_history (
        history_id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        rule_name TEXT NOT NULL,
        condition TEXT NOT NULL,
        action TEXT NOT NULL,
        changed_by TEXT NOT NULL,
        changed_at TEXT NOT NULL,
        change_reason TEXT NOT NULL
    )
    ''')
    
    # 4. Model Versions Table: Model registry for ML governance and deterministic rollback
    # Keys/Constraints: PRIMARY KEY (version_id)
    # Versioning/Audit: model_artifact_path, is_active flag (only 1 active at a time), created_by, created_at
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS model_versions (
        version_id TEXT PRIMARY KEY,
        model_name TEXT NOT NULL,
        contamination REAL NOT NULL,
        rarity_threshold REAL NOT NULL,
        score_threshold REAL NOT NULL,
        fp_reduction_rate REAL NOT NULL,
        missed_incidents INTEGER NOT NULL,
        missed_incident_rate REAL NOT NULL,
        model_artifact_path TEXT NOT NULL,
        is_active INTEGER DEFAULT 0,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        notes TEXT
    )
    ''')
    
    # 5. Audit Log Table: Immutable SOC event stream
    # Keys/Constraints: PRIMARY KEY (id AUTOINCREMENT)
    # Fields: timestamp, user, action, target_type, target_id, details, status
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        user TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        details TEXT NOT NULL,
        status TEXT NOT NULL
    )
    ''')
    
    # 6. Users Table: Role-Based Access Control (RBAC) definitions
    # Keys/Constraints: PRIMARY KEY (username)
    # Roles: admin, lead_analyst, analyst
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')
    
    # Seed default users if not present
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users VALUES ('admin', 'admin', 'admin123')")
        cursor.execute("INSERT INTO users VALUES ('lead_sec', 'lead_analyst', 'lead123')")
        cursor.execute("INSERT INTO users VALUES ('analyst_jdoe', 'analyst', 'analyst123')")
        cursor.execute("INSERT INTO users VALUES ('analyst_asmith', 'analyst', 'analyst123')")
    
    # Seed default baseline rules if not present
    cursor.execute("SELECT COUNT(*) FROM rules")
    if cursor.fetchone()[0] == 0:
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        default_rules = [
            ('RULE-WEB-SQLI-21', 'SQLi Protection', 'High', 'Detects SQL Injection strings in URL parameters', 'event_type == "SQL Injection Attempt"', 'Escalate / True Incident', 1, 1, 'admin', now),
            ('RULE-PRIV-ESC-22', 'Privilege Escalation Detector', 'Critical', 'Detects unauthorized privilege escalation attempts', 'event_type == "Privilege Escalation Exploit"', 'Escalate / Critical Incident', 1, 1, 'admin', now),
            ('RULE-RANSOM-ENC-23', 'Ransomware Canary', 'Critical', 'Detects rapid file extension renaming or encryption', 'event_type == "Ransomware File Encryption"', 'Escalate / Critical Incident', 1, 1, 'admin', now),
            ('RULE-NET-SCAN-01', 'Routine Vulnerability Scanner Filter', 'Low', 'Identifies scheduled internal scanner activity', 'event_type == "Routine Vulnerability Scan" and source_ip.startswith("10.")', 'Dismiss / False Positive', 1, 1, 'admin', now),
            ('RULE-SYS-BACKUP-02', 'Scheduled Backup Exemption', 'Low', 'Allows scheduled high-volume backup processes', 'event_type == "Scheduled Backup Spike" and user.startswith("svc_")', 'Dismiss / False Positive', 1, 1, 'admin', now)
        ]
        cursor.executemany("INSERT INTO rules VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", default_rules)
        for r in default_rules:
            cursor.execute(
                "INSERT INTO rule_history (rule_id, version, rule_name, condition, action, changed_by, changed_at, change_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (r[0], r[6], r[1], r[4], r[5], 'system', now, 'Initial rule provisioning')
            )
            
    # Seed default model versions if not present
    cursor.execute("SELECT COUNT(*) FROM model_versions")
    if cursor.fetchone()[0] == 0:
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        base_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'model', 'model_v1_baseline.pkl')
        tuned_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'model', 'model_v2_tuned.pkl')
        cursor.execute('''
        INSERT INTO model_versions VALUES 
        ('v1.0.0-baseline', 'Isolation Forest Baseline', 0.01, 0.95, 0.258, 3.33, 0, 0.0, ?, 0, 'admin', ?, 'Initial baseline model before QBee fine-tuning'),
        ('v2.0.0-tuned', 'Isolation Forest Tuned', 0.05, 0.15, 0.05, 100.0, 0, 0.0, ?, 1, 'admin', ?, 'Fine-tuned model satisfying QBee requirement 1')
        ''', (base_path, now, tuned_path, now))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully.")
