# Explainable AI-Enabled Random Forest Intrusion Detection System (IDS)

A modular, hybrid Network and Host Intrusion Detection System (NIDS/HIDS) combining machine learning classification with **Explainable AI (XAI)** using **SHAP (SHapley Additive exPlanations)** and **Random Forest**. Designed for real-time network threat detection, root-cause analyst verification, and host integrity monitoring.

---

## 🌟 Key Features

- **Explainable AI (XAI) Engine (`src/ml/`):**
  - **Random Forest Classification:** Trained on the benchmark **CIC-IDS2017** dataset (78 network features) to identify malicious flow signatures (DDoS, PortScan, Brute Force, etc.).
  - **SHAP TreeExplainer:** Generates real-time feature attribution scores for flagged alerts, highlighting the top 3 root-cause network indicators (e.g., packet rate spikes, flow duration anomalies).
  - **Explanation & Analyst Evaluation Framework (`evaluate.py`):** Quantitative metrics comparing raw model confidence vs. SHAP-enhanced confidence, plus synthetic and interactive analyst decision-making speedup/accuracy benchmarks.

- **Network Intrusion Detection System (NIDS) (`src/nids/`):**
  - **Live & Offline Capture:** Supports live interface sniffing via Scapy (e.g., `eth0`) and offline `.pcap` file replay analysis.
  - **Stateful Flow Aggregation:** Aggregates raw IP packets into bidirectional session flows (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`) with active timeout cleanup and packet threshold triggers.
  - **CIC-IDS2017 Feature Extraction:** Dynamically extracts 78 statistical network flow features aligned with standard IDS dataset schemas.

- **Host Intrusion Detection System (HIDS) (`src/hids/`):**
  - **File Integrity Monitor (FIM):** Cryptographic SHA-256 hash tracking with baseline snapshot comparison (`data/baseline.json`) for recursive directory change, deletion, or creation detection.
  - **System Log Monitor:** Real-time tailing of system authentication logs (e.g., `/var/log/auth.log`) using regex patterns for suspicious logon attempts.

- **Decoupled Event-Driven Core (`src/core/`):**
  - Publish-subscribe internal `EventBus` (`new_packet`, `analyze_flow`, `security_alert`).
  - Centralized thread-safe system (`logs/system.log`) and security alert (`logs/alerts.log`) logging with fallback for restricted permissions.

---

## 🏗️ Architecture & Data Flow

```
                                +-------------------+
                                |   Raw Packets     |
                                | (Live / PCAP)     |
                                +---------+---------+
                                          |
                                          v
                                +-------------------+
                                |   NIDSSniffer     |
                                +---------+---------+
                                          | [event: new_packet]
                                          v
                                +-------------------+
                                |   FlowManager     |
                                +---------+---------+
                                          | [event: analyze_flow]
                                          v
                                +-------------------+
                                |     MLEngine      |
                                | (Random Forest)   |
                                +---------+---------+
                                          | [Inference & SHAP Explainer]
                                          v
+-------------------+           +-------------------+
|  FileIntegrity &  |           |   Security Alert  |
|   Log Monitors    +---------->+   & Log Outputs   |
|     (HIDS)        |           | (logs/alerts.log) |
+-------------------+           +-------------------+
```

---

## 📁 Repository Structure

```
.
├── main.py                     # Main entrypoint for launching Hybrid IDS
├── evaluate.py                 # CLI launcher for SHAP XAI evaluation & analyst study
├── requirements.txt            # Python dependencies
├── ARCHITECTURE.md             # Detailed system architectural documentation
├── data/                       # Dataset directory (CIC-IDS2017 CSVs & FIM baseline)
├── models/                     # Saved ML model weights (.joblib)
├── logs/                       # System logs, alerts, and evaluation JSON reports
├── src/
│   ├── core/                   # EventBus and centralized Logger
│   │   ├── event_bus.py
│   │   └── logger.py
│   ├── nids/                   # Packet sniffing and bidirectional flow management
│   │   ├── sniffer.py
│   │   └── flow_manager.py
│   ├── hids/                   # File integrity & log monitoring modules
│   │   ├── file_integrity.py
│   │   ├── log_monitor.py
│   │   └── manager.py
│   └── ml/                     # ML training, feature extraction, SHAP engine & evaluation
│       ├── train.py
│       ├── feature_extractor.py
│       ├── engine.py
│       └── evaluate_explanations.py
└── tests/                      # Unit & integration tests
```

---

## 🚀 Quick Start

### 1. Environment Setup

Clone the repository and install requirements in a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Model Training

Download the **CIC-IDS2017** dataset CSV files from the [UNB Official Source](https://www.unb.ca/cic/datasets/ids-2017.html) and place them inside the `data/` directory.

Run the trainer:
```bash
python3 src/ml/train.py
```
*Note: If no CSV data is detected in `data/`, the trainer automatically generates synthetic demonstration data to verify the pipeline. Model artifacts (`ids_model.joblib`, `scaler.joblib`, `label_encoder.joblib`) will be saved in `models/`.*

### 3. Run the Hybrid IDS

To start live monitoring (requires root privileges for network sniffing):

```bash
sudo python3 main.py eth0
```

To replay an offline `.pcap` capture file:
```python
# Pass pcap_file to HybridIDS in main.py or instantiate HybridIDS(pcap_file="path/to/capture.pcap")
```

### 4. Evaluate SHAP Explanations & Analyst Impact

Assess how Explainable AI affects detection confidence and analyst verification speed:

```bash
# Automated evaluation on test sample
python3 evaluate.py --sample-size 200

# Run interactive analyst study mode
python3 evaluate.py --sample-size 10 --interactive
```

Evaluation outputs and reports are exported to `logs/explanation_evaluation_report.json`.

---

## 📊 Evaluation & Metrics

The XAI evaluation module assesses:
1. **Detection Confidence Gain:** Combines prediction output probabilities with normalized SHAP feature stability scores.
2. **Analyst Decision Performance:** Measures alert verification speedup (seconds per alert), classification decision accuracy, and analyst confidence scores with vs. without SHAP explanations.

---

## 🛡️ License

This project is licensed under the [MIT License](LICENSE).
