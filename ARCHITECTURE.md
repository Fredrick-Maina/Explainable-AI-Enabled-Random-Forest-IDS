# Hybrid AI-IDS Architecture

## Overview
This project is a modular Intrusion Detection System (IDS) that combines traditional signature-based detection with modern Machine Learning (AI) analysis. It is designed to be extensible, allowing for both Network-based (NIDS) and Host-based (HIDS) monitoring.

## Directory Structure
- `src/core/`: Central orchestration, logging, and communication (Event Bus).
- `src/nids/`: Network sniffing, packet processing, and flow aggregation.
- `src/hids/`: Host monitoring (File integrity, log analysis).
- `src/ml/`: Feature extraction and AI model inference (Supervised/Unsupervised).
- `models/`: Storage for pre-trained AI model weights.
- `data/`: Storage for datasets (e.g., CIC-IDS2017) used for training/validation.

## Data Flow
1. **Network Capture (NIDS):**
    - The `nids` module sniffs raw packets and groups them into bidirectional "flows" via `FlowManager`.
    - `MLEngine` transforms flows into feature vectors for classification/anomaly detection.
2. **Host Monitoring (HIDS):**
    - **File Integrity:** `FileIntegrityMonitor` compares cryptographic hashes of sensitive files against a baseline.
    - **Log Analysis:** `LogMonitor` tails system logs (e.g., `/var/log/auth.log`) for suspicious patterns using Regex.
3. **Detection & Alerting:**
    - Any module (NIDS, HIDS, ML) can emit a `security_alert` via the `EventBus`.
    - The `core.logger` captures these alerts into `logs/alerts.log` and `logs/system.log`.

## Cross-Platform Support
The system is designed to be platform-aware, although it is optimized for Linux/Kali.
- **OS Detection:** Uses the `platform` module in `main.py` to identify the host operating system.
- **Network Interfaces:** The `NIDSSniffer` defaults to `None` for the interface, allowing Scapy to automatically select the default system interface if one isn't explicitly provided via CLI.
- **Log Monitoring:** 
    - **Linux:** Default-monitors `/var/log/auth.log`.
    - **Windows/macOS:** Fallback paths are provided, though full log parsing for these platforms is a future roadmap item.
- **Paths & Permissions:** The `core.logger` uses defensive programming to handle `PermissionError` (e.g., when `/logs` is root-owned) by falling back to current-directory or console logging.

