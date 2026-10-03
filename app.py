import os
import pandas as pd
from flask import Flask, jsonify, render_template, request, session
from utils.db import init_db, get_db_connection
from utils.recommend import predict_single_alert
from routes.alert_routes import alert_bp
from routes.upload_routes import upload_bp
from routes.change_review import change_bp
from routes.model_routes import model_bp
from routes.audit_routes import audit_bp

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.secret_key = 'sec-alert-ai-dev-secret-key-qbee'
    
    # Register API Blueprints
    app.register_blueprint(alert_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(change_bp)
    app.register_blueprint(model_bp)
    app.register_blueprint(audit_bp)
    
    # Initialize DB schema
    init_db()
    
    # Populate initial alerts from dataset if DB is empty
    seed_alerts_if_needed()
    
    # Web UI Page Routes (Jinja2 templates)
    @app.route('/')
    def index_page():
        return render_template('index.html')
        
    @app.route('/investigation')
    def investigation_page():
        return render_template('investigation.html')
        
    @app.route('/upload')
    def upload_page():
        return render_template('upload.html')
        
    @app.route('/change-review')
    def change_review_page():
        return render_template('change_review.html')
        
    @app.route('/model')
    def model_page():
        return render_template('model.html')
        
    @app.route('/analytics')
    def analytics_page():
        return render_template('analytics.html')
        
    @app.route('/audit')
    def audit_page():
        return render_template('audit.html')
        
    @app.route('/health')
    def health_check():
        return jsonify({'status': 'healthy', 'service': 'security-alert-ai-app'})
        
    return app

def seed_alerts_if_needed():
    dataset_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dataset', 'security_alerts_2000.csv')
    if not os.path.exists(dataset_file):
        return
        
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
    if count < 100:
        print("Seeding alerts database from security_alerts_2000.csv...")
        df = pd.read_csv(dataset_file)
        
        from utils.recommend import get_preprocessor, get_model
        from model.novelty import compute_rarity_scores, score_alert_anomaly
        from model.decision import make_alert_recommendation
        from model.config import load_config
        
        preprocessor = get_preprocessor()
        model = get_model()
        config = load_config()
        
        if preprocessor.is_fitted:
            X = preprocessor.transform(df)
            rarities = compute_rarity_scores(df, preprocessor)
        else:
            preprocessor.fit(df)
            X = preprocessor.transform(df)
            rarities = compute_rarity_scores(df, preprocessor)
            
        scores, preds = score_alert_anomaly(model, X)
        
        records = []
        for i, (_, row) in enumerate(df.iterrows()):
            rec = make_alert_recommendation(row, scores[i], rarities[i], preds[i], config)
            records.append((
                row['alert_id'],
                row['timestamp'],
                row['severity'],
                row['event_type'],
                row['source_ip'],
                row['destination_ip'],
                row['user'],
                row['endpoint'],
                row['rule_name'],
                row['ground_truth'],
                row.get('analyst_disposition', row['ground_truth']),
                'analyst_baseline',
                rec['recommendation'],
                rec['confidence'],
                float(scores[i]),
                float(rarities[i]),
                'closed' if row['ground_truth'] == 'false_positive' else 'escalated',
                '',
                '[]'
            ))
            
        conn.executemany('''
        INSERT OR REPLACE INTO alerts 
        (alert_id, timestamp, severity, event_type, source_ip, destination_ip, user, endpoint, rule_name, ground_truth, analyst_disposition, analyst_user, model_recommendation, model_confidence, anomaly_score, rarity_score, status, override_reason, disposition_history)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', records)
        conn.commit()
        print(f"Seeded {len(records)} alerts.")
    conn.close()

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
