# Hybrid AI-Intrusion Detection System (IDS)

## Overview
A modular hybrid NIDS/HIDS project designed for security education, CTF competitions, and real-time threat detection using Machine Learning.

## Architecture
The project is structured into four main domains:
- **`src/nids/`**: Flow-based network sniffing and aggregation.
- **`src/ml/`**: AI Engine utilizing the CIC-IDS2017 feature set for supervised classification and unsupervised anomaly detection.
- **`src/core/`**: Orchestration via an internal Event Bus and centralized logging.
- **`src/hids/`**: Host integrity and log monitoring.

For detailed design information, see `ARCHITECTURE.md`.

## Features
- **Flow Aggregation:** Groups raw packets into bidirectional sessions with timeout management for stale flows.
- **AI-Powered Detection:** Integrated with CIC-IDS2017 feature extraction (Enhanced to capture directionality and header data).
- **Hybrid Strategy:** Supports Random Forest models for known attacks and Autoencoders for anomalies.
- **Event-Driven:** Decoupled architecture for easy extension.
- **Recursive HIDS:** Monitors entire directories for unauthorized file modifications, deletions, or new file creations.

## Usage

### 1. Install Prerequisites
```bash
pip install -r requirements.txt
```

### 2. Train the AI Model
- Download the **CIC-IDS2017** dataset (CSV format) from the [Official Source](https://www.unb.ca/cic/datasets/ids-2017.html).
- Place the CSV files in the `data/` directory.
- Run the training script:
  ```bash
  python3 src/ml/train.py
  ```
  *(Note: Training on the full 2.8M rows may require high RAM. Consider using a subset for the first iteration.)*
- This will generate `ids_model.joblib`, `scaler.joblib`, and `label_encoder.joblib` in the `models/` directory.

### 3. Run the IDS
```bash
sudo python3 main.py [interface]
```
*(Default interface is eth0 if none provided)*

### 4. Monitor Logs
- General logs: `logs/system.log`
- Security alerts: `logs/alerts.log`

## Roadmap
- [x] Implement Host Integrity Monitoring (HIDS) with recursive directory support.
- [ ] Integrate pre-trained Random Forest model for DDoS/SQLi detection (Ongoing feature set refinement).
- [ ] Develop a web dashboard for real-time visualization.
