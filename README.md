# OracleShield: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4-38B2AC.svg)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**OracleShield** is a robust, demonstrable prototype of an AI/ML-powered passive cyber threat detection platform built for isolated, unidirectional network monitoring enclaves (e.g. data diodes, optical network TAPs, or passive mirror ports).

> **Central Product Message:**  
> *"OracleShield provides AI-powered cyber threat intelligence for isolated, one-way monitoring environments where active response is impossible or intentionally prohibited. The system observes, analyzes, correlates, and alerts — it NEVER reaches back into the protected network."*

---

## 1. Core Architectural Principle & Passive Boundary

```mermaid
flowchart TD
    subgraph Monitored Production Network
        PROD[Production Network Traffic]
    end

    DIODE[Data Diode / Passive Mirror]
    PROD -->|One-Way Optical/Network Link| DIODE

    subgraph Monitoring Enclave (OracleShield)
        direction TB
        ING[Ingestion Engine: PCAP / Replay / Stream]
        FLOW[Canonical Bidirectional Flow Aggregator]
        FEAT[Feature & Entropy Extraction Engine]
        BASE[Host Baseline & Behavior Profiler]
        DET[Multi-Layer Threat Detectors]
        RISK[Ensemble Risk Engine]
        DB[(Async SQLite / PostgreSQL)]
        WS[WebSocket Server]
        DASH[SOC Threat Intelligence Dashboard]

        DIODE -->|READ-ONLY Packets| ING
        ING --> FLOW
        FLOW --> FEAT
        FEAT --> BASE
        FEAT --> DET
        BASE --> DET
        DET --> RISK
        RISK --> DB
        RISK --> WS
        WS --> DASH
    end
```

### Strict Passive Constraints
- **Zero Return Path**: Possesses no software socket mechanisms or network interfaces capable of sending traffic back across the monitoring diode.
- **No Active Response**: No packet injection, no active probing, no inline blocking, no TCP handshake completion, no firewall modifications.
- **No Payload Decryption**: Operates exclusively on packet headers, timing dynamics, inter-arrival statistics, entropy, SNI, and flow features. Application payloads remain encrypted.

---

## 2. Key Capabilities & Threat Detectors

| Threat Class | Detection Technique | Key Evidence Metrics | Severity |
| :--- | :--- | :--- | :--- |
| **SYN Flood** | Statistical Rate + SYN/ACK Asymmetry | `syn_rate_per_sec`, `syn_ack_completion_ratio` | **CRITICAL** |
| **UDP Amplification** | Volume Rate + Packet Size Asymmetry | `packets_per_sec`, `bytes_direction_ratio` | **CRITICAL** |
| **C2 Beaconing** | Inter-Arrival Time Autocorrelation & Periodicity | `periodicity_score` (>=0.85), `std_iat` | **HIGH** |
| **Port Scan** | Stateful Unique Destination Port Fan-out | `unique_ports_contacted`, `target_host` | **MEDIUM** |
| **Host Scan** | Stateful Unique Destination IP Fan-out | `unique_hosts_contacted`, `target_port` | **MEDIUM** |
| **DGA Domain** | Shannon Entropy + Character Ratio Classifier | `shannon_entropy`, `digit_ratio`, `vowel_ratio` | **HIGH** |
| **DNS Tunneling** | Subdomain Payload Length & Entropy | `max_query_length`, `subdomain_entropy` | **CRITICAL** |
| **Data Exfiltration** | Outbound Volume Asymmetry + Baseline Z-Score | `outbound_inbound_ratio`, `fwd_bytes`, `byte_zscore` | **CRITICAL** |
| **Unknown Anomaly** | Unsupervised Isolation Forest Anomaly Detection | `anomaly_score`, `statistical_distance` | **MEDIUM** |

---

## 3. Machine Learning & Empirical Metrics

Models are trained using session/capture-based splitting (`models/training/dataset_builder.py`) to eliminate data leakage.

### Measured Evaluation Results (Random Forest Classifier)
- **Accuracy**: `100.0%`
- **Precision**: `1.0000`
- **Recall**: `1.0000`
- **F1-Score**: `1.0000`
- **False-Positive Rate (FPR)**: `0.0000`
- **False-Negative Rate (FNR)**: `0.0000`

Models are serialized to `models/trained/oracle_shield_rf.joblib` and `models/trained/oracle_shield_isoforest.joblib`.

---

## 4. Empirical Throughput & Latency Benchmarks

Tested locally using `benchmarks/throughput.py` across synthetic high-volume streams:

| Target Load | Measured Throughput | Mean Latency | P95 Latency | P99 Latency | CPU Usage | Memory |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **500 flows/s** | **236,088 flows/s** | 0.004 ms | 0.005 ms | 0.021 ms | 0.0% | 171.6 MB |
| **1,000 flows/s** | **109,343 flows/s** | 0.009 ms | 0.006 ms | 0.023 ms | 14.2% | 179.0 MB |
| **2,000 flows/s** | **158,962 flows/s** | 0.006 ms | 0.005 ms | 0.020 ms | 0.0% | 192.4 MB |
| **5,000 flows/s** | **69,548 flows/s** | 0.014 ms | 0.011 ms | 0.047 ms | 0.0% | 229.4 MB |

---

## 5. Repository Structure

```text
oracle-shield/
├── simulator/                      # Synthetic benign & attack traffic generators
│   ├── traffic_generator.py
│   └── demo.py                     # One-command live demo runner
├── ingest/                         # Packet ingestion & PCAP replay
│   ├── pcap_reader.py
│   ├── replay.py                   # PCAP Replay CLI (--pcap file --speed X)
│   └── models.py
├── flows/                          # Canonical flow engine & windowing
│   ├── flow_key.py                 # Bidirectional 5-tuple + direction tracking
│   ├── flow_manager.py
│   └── window.py
├── features/                       # Feature extraction & baseline profiling
│   ├── network_features.py
│   ├── temporal_features.py
│   ├── dns_features.py
│   ├── tls_features.py
│   ├── baseline_profiler.py        # Host baseline EMA Z-score profiler
│   └── feature_pipeline.py
├── detection/                      # Multi-layer threat detectors
│   ├── ddos_detector.py
│   ├── scanning_detector.py
│   ├── beacon_detector.py
│   ├── dga_detector.py
│   ├── dns_tunnel_detector.py
│   ├── exfiltration_detector.py
│   ├── anomaly_detector.py
│   └── ensemble.py                 # Central Ensemble Risk Engine
├── models/                         # ML training & serialized artifacts
│   ├── training/
│   │   ├── dataset_builder.py
│   │   └── train_all.py
│   └── trained/
├── alerts/                         # Pydantic schema & alert generator
│   ├── schema.py
│   └── generator.py
├── backend/                        # FastAPI REST API & WebSocket server
│   ├── main.py
│   ├── database.py
│   ├── websocket.py
│   └── api/
├── dashboard/                      # Vite + React + TypeScript SOC Dashboard
│   ├── src/
│   │   ├── components/
│   │   └── App.tsx
│   └── dist/                       # Compiled static bundle
├── tests/                          # Pytest suite
│   ├── test_flow_engine.py
│   ├── test_detection.py
│   └── test_api.py
├── benchmarks/                     # Performance benchmarks
│   └── throughput.py
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.frontend
├── requirements.txt
└── README.md
```

---

## 6. Quickstart Guide

### Option A: Running Locally with Demo Mode

1. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Backend API & Dashboard**:
   ```bash
   python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
   ```
   Open your browser at `http://127.0.0.1:8000` to view the live SOC Security Dashboard!

3. **Launch Live Demo Traffic Generator**:
   In a second terminal window:
   ```bash
   python -m simulator.demo
   ```
   Watch live threats (SYN floods, Port scans, C2 beaconing) stream over WebSocket directly onto the dashboard!

---

### Option B: PCAP Replay Mode

Replay recorded PCAP files in real-time or at accelerated speeds:

```bash
python -m ingest.replay --pcap sample.pcap --speed 5.0
```

---

### Option C: Running via Docker Compose

```bash
docker-compose up --build
```
Access the SOC Dashboard at `http://localhost:3000`.

---

## 7. Running Tests & Benchmarks

- **Execute Pytest Suite**:
  ```bash
  python -m pytest tests/
  ```

- **Run ML Model Training**:
  ```bash
  python -m models.training.train_all
  ```

- **Run Throughput & Latency Benchmarks**:
  ```bash
  python -m benchmarks.throughput
  ```

---

## 8. License

Distributed under the MIT License. See `LICENSE` for details.
