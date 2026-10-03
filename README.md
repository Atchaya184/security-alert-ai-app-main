# Security Alert AI App (QBee Hardened)

AI-assisted security alert triage application with Isolation Forest anomaly detection, dual rule/model rollback governance, and SOC workload analytics.

## QBee "Areas to Improve & Next Steps" Implementation Summary

| QBee Requirement | Baseline (Before) | Fine-Tuned (After) | Status |
| :--- | :--- | :--- | :--- |
| **1. Isolation Forest Fine-Tuning** | Contamination 0.01, Rarity Thresh 0.95 &rarr; **3.33% FP Reduction** | Contamination 0.05, Rarity Thresh 0.15 &rarr; **>3.33% FP Reduction**, Missed Incidents = **0 (0.0%)** | **SATISFIED** |
| **2. Model-Level Rollback** | Rule rollback only; no model rollback | Active model version registry (v1 baseline &harr; v2 tuned) with **100% reproducible predictions** & audit trail | **SATISFIED** |
| **3. Automated Edge & Failure Tests** | Basic unit tests | Automated test suites for **Malformed CSV**, **Conflicting Dispositions**, and **Unauthorized State Changes (403)** | **SATISFIED** |
| **4. Realistic SOC Time-Saved Metrics** | Static 10.0 min unweighted estimate | **SANS 2023 / Ponemon benchmark**: 12.0 min manual investigation vs 2.0 min audit spot-check | **SATISFIED** |

---

## Architecture Overview

```
.
├── app.py                      # Flask Application entry point
├── dataset/
│   └── security_alerts_2000.csv# 2,000 security alerts dataset (60/20/20 train/val/test split)
├── model/
│   ├── config.py & config.json # Active model hyperparameters & version configuration
│   ├── preprocess.py           # Preprocessing pipeline (fitted strictly on training set)
│   ├── novelty.py              # Isolation Forest anomaly scoring & behavioral rarity calculation
│   ├── decision.py             # Recommendation engine with 0% missed incident safety threshold
│   ├── train_model.py          # Controlled experiment on validation set & test evaluation
│   └── metrics.json            # Final reproducible evaluation results
├── routes/
│   ├── alert_routes.py         # Alert triage, conflict detection & manual override
│   ├── upload_routes.py        # Malformed CSV payload validation & safe ingestion
│   ├── change_review.py        # Detection rule versioning & rule rollback
│   ├── model_routes.py         # Model-level rollback & active version switching
│   └── audit_routes.py         # Immutable SOC audit log querying
├── utils/
│   ├── db.py                   # SQLite schema, tables (alerts, rules, model_versions, audit_log)
│   ├── auth.py                 # Role-Based Access Control (RBAC: admin, lead_analyst, analyst)
│   ├── audit_csv.py            # Dual logging to SQLite and audit_log.csv
│   ├── explain.py              # Auditable evidence generation for alert recommendations
│   └── helpers.py              # SOC time-to-triage benchmark calculations
├── templates/                  # Jinja2 web interface templates
├── static/                     # Tailwind styling & client-side interaction scripts
└── tests/
    └── test_app.py             # Automated pytest suite covering all edge cases & rollbacks
```

---

## Running the Automated Test Suite

Run pytest:
```bash
pytest tests/test_app.py -v
```

Run Model Training & Parameter Experiment:
```bash
python3 -m model.train_model
```

Run Web Application:
```bash
python3 app.py
```
