# RT-TTA: Real-Time TOR Traffic Analyzer
## Complete Project Documentation

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Analysis Modules](#analysis-modules)
5. [Models](#models)
6. [Utilities](#utilities)
7. [Dashboard](#dashboard)
8. [Workflow Diagrams](#workflow-diagrams)
9. [Key Features](#key-features)
10. [Technical Specifications](#technical-specifications)

---

## 🎯 Project Overview

**RT-TTA (Real-Time TOR Traffic Analyzer)** is a comprehensive forensic analysis system designed to:

- Detect TOR network traffic in real-time
- Identify Entry Guards, Middle Relays, and Exit Nodes
- Perform traffic correlation attacks for de-anonymization
- Generate forensic intelligence reports
- Monitor the global TOR network consensus

### Problem Statement

TOR (The Onion Router) anonymizes internet traffic by routing it through multiple relays. This project aims to:

1. **Detect** TOR traffic on a network
2. **Identify** which TOR nodes are being used
3. **Correlate** Entry-Exit traffic to trace origins
4. **Generate** actionable forensic intelligence

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        STREAMLIT DASHBOARD                          │
│                           (app.py)                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐│
│  │   Capture   │  │ Correlation │  │   Alerts    │  │   Global    ││
│  │  & Analyze  │  │   Attack    │  │   Monitor   │  │   Monitor   ││
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘│
│         │                │                │                │       │
├─────────┼────────────────┼────────────────┼────────────────┼───────┤
│         ▼                ▼                ▼                ▼       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    ANALYSIS LAYER                           │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │   │
│  │  │   Origin    │ │ Correlation │ │  Activity   │           │   │
│  │  │   Tracer    │ │   Attack    │ │ Fingerprint │           │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │   │
│  │  │   Burst     │ │  Real-Time  │ │  Website    │           │   │
│  │  │ Correlator  │ │ Correlation │ │ Fingerprint │           │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                     │
├──────────────────────────────┼─────────────────────────────────────┤
│                              ▼                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      CORE LAYER                             │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │   │
│  │  │   Stream    │ │  Consensus  │ │Entry Guard  │           │   │
│  │  │  Ingester   │ │  Fetcher    │ │  Analyzer   │           │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │   │
│  │  │   Flow      │ │   Circuit   │ │   Alert     │           │   │
│  │  │  Extractor  │ │   Monitor   │ │   System    │           │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │   │
│  │  ┌─────────────┐ ┌─────────────┐                           │   │
│  │  │    JA3      │ │  Tor Consens│                           │   │
│  │  │Fingerprinter│ │   Updater   │                           │   │
│  │  └─────────────┘ └─────────────┘                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                     │
├──────────────────────────────┼─────────────────────────────────────┤
│                              ▼                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    MODELS LAYER                             │   │
│  │  ┌─────────────────────┐  ┌─────────────────────┐          │   │
│  │  │   Deep Classifier   │  │   (Future Models)   │          │   │
│  │  │   (Neural Network)  │  │                     │          │   │
│  │  └─────────────────────┘  └─────────────────────┘          │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                     │
├──────────────────────────────┼─────────────────────────────────────┤
│                              ▼                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   EXTERNAL DATA                             │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │   │
│  │  │   Onionoo   │ │   Network   │ │ TOR Control │           │   │
│  │  │     API     │ │  Interface  │ │    Port     │           │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Core Components

### 1. Stream Ingester (`core/stream_ingester.py`)

**Purpose:** Real-time packet capture from network interfaces

**Key Features:**
- Live packet capture using Scapy
- Network interface enumeration
- Packet filtering (TCP/UDP)
- Threaded capture for non-blocking operation

**Workflow:**
```
Network Interface → Scapy Sniff → Packet Queue → Flow Extractor
```

**Key Functions:**
| Function | Description |
|----------|-------------|
| `get_available_interfaces()` | Lists network interfaces |
| `start_capture()` | Begins packet capture |
| `process_packet()` | Handles each captured packet |

---

### 2. Flow Extractor (`core/flow_extractor.py`)

**Purpose:** Aggregates packets into bidirectional network flows

**Key Features:**
- 5-tuple flow identification (src_ip, src_port, dst_ip, dst_port, proto)
- Flow timeout management
- Statistical feature extraction

**Flow Features Extracted:**
| Feature | Description |
|---------|-------------|
| `packet_count` | Total packets in flow |
| `byte_count` | Total bytes transferred |
| `duration` | Flow duration in seconds |
| `iat_mean` | Mean Inter-Arrival Time |
| `iat_std` | Standard deviation of IAT |

---

### 3. Consensus Fetcher (`core/consensus_fetcher.py`)

**Purpose:** Fetches TOR network consensus data from Onionoo API

**Data Retrieved:**
- All active TOR relays (~9,000+)
- Relay flags (Guard, Exit, Stable, Fast)
- IP addresses and ports
- Bandwidth information
- Country/ASN data

**API Endpoint:** `https://onionoo.torproject.org/details`

**Workflow:**
```
Onionoo API → JSON Response → Parse Relays → Build IP Lookup → Cache
```

---

### 4. Entry Guard Analyzer (`core/entry_guard_analyzer.py`)

**Purpose:** Identifies and analyzes TOR Entry Guard connections

**Detection Methods:**
1. **IP Matching:** Compare destination IP against consensus Entry Guards
2. **Port Analysis:** TOR typically uses ports 9001, 443
3. **TLS Fingerprinting:** Match JA3 fingerprints
4. **Traffic Pattern:** Analyze timing patterns

**Output:**
| Field | Description |
|-------|-------------|
| `is_entry_guard` | Boolean detection result |
| `confidence` | Detection confidence (0-1) |
| `guard_info` | Relay nickname, country, bandwidth |

---

### 5. Circuit Monitor (`core/circuit_monitor.py`)

**Purpose:** Connects to local TOR daemon to monitor active circuits

**Requirements:** TOR running with Control Port (9051)

**Features:**
- Real-time circuit enumeration
- Entry → Middle → Exit path visibility
- Stream-to-circuit mapping
- Circuit purpose detection (GENERAL, HS_CLIENT)

**Key Classes:**
| Class | Description |
|-------|-------------|
| `TorRelay` | Single relay information |
| `TorCircuit` | Complete circuit path |
| `TorStream` | Active stream data |
| `TorCircuitMonitor` | Main monitoring class |

---

### 6. JA3 Fingerprinter (`core/ja3_fingerprinter.py`)

**Purpose:** TLS fingerprinting for traffic classification

**JA3 Formula:**
```
JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
```

**Known TOR JA3 Hashes:**
- Standard TOR Client patterns
- TOR Browser signatures
- Pluggable transport fingerprints

---

### 7. Alert System (`core/alert_system.py`)

**Purpose:** Real-time security alerting with SIEM integration

**Alert Types:**
| Type | Trigger |
|------|---------|
| `HIDDEN_SERVICE` | HS_CLIENT connection detected |
| `BOTNET_PATTERN` | Regular IAT < 0.3 CV |
| `CORRELATION_MATCH` | Entry-Exit correlation > 0.65 |
| `ORIGIN_IDENTIFIED` | Origin traced with > 80% confidence |

**Severity Levels:** CRITICAL → HIGH → MEDIUM → LOW

**SIEM Export:** JSON Lines format for Splunk/ELK

---

### 8. TOR Consensus Updater (`core/tor_consensus_updater.py`)

**Purpose:** Background thread that keeps consensus data fresh

**Features:**
- Automatic refresh every 5 minutes
- Thread-safe data access
- Search and filter capabilities
- Country/role aggregation

---

## 📊 Analysis Modules

### 1. Origin Tracer (`analysis/origin_tracer.py`)

**Purpose:** Traces Probable Origin IP from TOR circuit data

**Algorithm:**
```
1. Load local network logs (PCAP/NetFlow)
2. Build time-indexed lookup table
3. Search for packets matching:
   - Timestamp ≈ Flow.local_entry_time (±2s)
   - Destination IP = Entry Guard IP
4. Return source IP as Probable Origin
```

**Composite Confidence Score (CCS):**
```
CCS = 0.45 × IdentityScore + 0.35 × FingerprintScore + 0.20 × PatternScore
```

**Weight Justification:**
| Component | Weight | Rationale |
|-----------|--------|-----------|
| Identity | 0.45 | Consensus matching is most reliable |
| Fingerprint | 0.35 | TLS fingerprints are strong indicators |
| Pattern | 0.20 | Traffic patterns can be mimicked |

---

### 2. Correlation Attack (`analysis/correlation_attack.py`)

**Purpose:** Entry-Exit traffic correlation for de-anonymization

**Attack Types:**

#### Timing Correlation Attack
```
1. Extract IAT sequences at Entry and Exit
2. Compute normalized cross-correlation
3. Check time offset (expect 0.3-2.0s TOR latency)
4. Calculate statistical significance (p-value)
```

**Correlation Metric:** Pearson correlation coefficient

#### Volume Correlation Attack
```
1. Compare packet counts
2. Compare total bytes (account for TOR overhead)
3. Compare average packet sizes
4. Weighted combination
```

**Combined Score:** 60% Timing + 40% Volume

---

### 3. Real-Time Correlation (`analysis/realtime_correlation.py`)

**Purpose:** Live packet capture with streaming correlation

**Workflow:**
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Capture   │───▶│   Flow      │───▶│   Check     │
│   Packet    │    │   Update    │    │   TOR IP    │
└─────────────┘    └─────────────┘    └─────────────┘
                                            │
                                            ▼
                   ┌─────────────┐    ┌─────────────┐
                   │   Display   │◀───│   Run       │
                   │   Results   │    │ Correlation │
                   └─────────────┘    └─────────────┘
```

**Key Features:**
- Sub-second packet processing
- Rolling window analysis
- Auto-refreshing dashboard
- Configurable capture duration

---

### 4. Website Fingerprinter (`analysis/website_fingerprinter.py`)

**Purpose:** Identify accessed websites from traffic patterns

**Features Extracted:**
| Feature | Description |
|---------|-------------|
| Packet count | Total packets |
| Byte distribution | Size histogram |
| Directional ratio | Upstream vs downstream |
| Burst patterns | Packet clusters |

**Templates:** Pre-trained patterns for known sites

---

### 5. Activity Fingerprinter (`analysis/activity_fingerprinter.py`)

**Purpose:** Classify traffic into activity categories

**Activity Types:**
| Type | Indicators |
|------|------------|
| `MARKETPLACE` | Mixed sizes, bursty, bidirectional |
| `BOTNET_C2` | Regular IAT, fixed sizes, periodic |
| `FILE_SHARING` | Large packets, asymmetric |
| `VIDEO_STREAMING` | Continuous, large downstream |
| `CHAT` | Small packets, irregular timing |

---

### 6. Burst Correlator (`analysis/burst_correlator.py`)

**Purpose:** Segment TCP streams and generate correlation fingerprints

**Circuit Segmentation:**
- Gap threshold (2.0s default)
- Minimum packets per segment
- Feature vector generation

**Watermark Generation:** SHA-256 hash of normalized features

---

## 🧠 Models

### Deep Classifier (`models/deep_classifier.py`)

**Purpose:** Neural network for traffic classification

**Architecture:**
```
Input Layer (Feature Vector)
    ↓
Dense(128, ReLU)
    ↓
Dropout(0.3)
    ↓
Dense(64, ReLU)
    ↓
Dropout(0.3)
    ↓
Dense(32, ReLU)
    ↓
Output Layer (Softmax)
```

**Input Features:**
- Statistical flow features
- Timing features
- Size distribution
- Directional features

**Output Classes:**
- TOR Traffic
- Non-TOR Traffic
- TOR Entry Guard
- TOR Exit Node

---

## 🛠️ Utilities

### Forensic Report Generator (`utils/forensic_report_generator.py`)

**Purpose:** Generate exportable forensic reports

**Required Fields (Hackathon Spec):**
| Field | Description |
|-------|-------------|
| Probable Origin IP | Traced local machine IP |
| Circuit Path | Entry, Middle, Exit (IP + Nickname) |
| Activity/Purpose | Circuit purpose code |
| Local Entry Timestamp | First packet timestamp |
| Composite Confidence Score | Weighted CCS value |
| Log Reference Pointer | Source file/timestamp |

**Export Formats:**
- JSON (detailed, nested)
- CSV (tabular, flat)

---

## 📱 Dashboard

### Main Application (`app.py`)

**Framework:** Streamlit

**Analysis Modes:**
1. 🧪 Synthetic Demo
2. 📂 Upload PCAP
3. 📡 Live Capture
4. 🌍 Global Network Monitor

**Global Monitor Tabs:**
| Tab | Purpose |
|-----|---------|
| 📡 Capture & Analyze | Live circuits + forensic tracing |
| ⚔️ Correlation Attack | Real-time attack simulation |
| 🚨 Alerts | Security alert monitoring |
| 🗺️ Countries | Geographic relay distribution |
| 🛡️ Guards | Entry Guard relay list |
| 🚪 Exits | Exit Node relay list |
| 🔍 Search | Relay search by name/IP |

---

## 🔄 Workflow Diagrams

### Complete Detection Workflow

```
┌──────────────────────────────────────────────────────────────────┐
│                     PACKET CAPTURE                                │
│  Network Interface → Scapy Sniff → Raw Packets                   │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                   FLOW EXTRACTION                                 │
│  Packets → 5-Tuple Grouping → Flow Objects → Feature Extraction  │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                   TOR DETECTION                                   │
│  IP Matching + JA3 Fingerprint + Port Analysis + Pattern Check   │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                 CORRELATION ATTACK                                │
│  Timing Analysis + Volume Analysis → Combined Score → Match      │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                  ORIGIN TRACING                                   │
│  Local Logs + Time Matching + Entry Guard IP → Probable Origin   │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                  REPORT GENERATION                                │
│  Forensic Finding → CCS Calculation → JSON/CSV Export            │
└──────────────────────────────────────────────────────────────────┘
```

---

## ⭐ Key Features

### Feature Summary

| Feature | Technology | Purpose |
|---------|------------|---------|
| Live Packet Capture | Scapy | Real-time traffic monitoring |
| TOR Consensus | Onionoo API | 9,000+ relay database |
| Circuit Monitoring | Stem Library | Entry-Middle-Exit path |
| JA3 Fingerprinting | TLS Analysis | Traffic classification |
| Correlation Attack | Statistical | De-anonymization |
| Forensic Reports | JSON/CSV | Actionable intelligence |
| SIEM Integration | JSON Lines | Enterprise security |
| Real-Time Alerts | Threshold | Automated detection |

### Model Key Features

| Feature | Importance | Calculation |
|---------|------------|-------------|
| IAT Mean | High | Mean packet inter-arrival time |
| IAT CV | High | Coefficient of variation |
| Packet Size Mean | Medium | Average packet size |
| Directional Ratio | Medium | Up/Down packet ratio |
| Flow Duration | Low | Total flow time |
| Burst Count | Medium | Packet clusters by IAT gap |

---

## 📐 Technical Specifications

### Dependencies

```
streamlit>=1.28.0
scapy>=2.5.0
stem>=1.8.0
requests>=2.28.0
pandas>=1.5.0
numpy>=1.23.0
plotly>=5.13.0
```

### System Requirements

- **OS:** Windows/Linux/macOS
- **Python:** 3.8+
- **Admin:** Required for packet capture
- **TOR:** Optional (for circuit monitoring)

### API Endpoints

| Service | URL | Rate Limit |
|---------|-----|------------|
| Onionoo Details | `https://onionoo.torproject.org/details` | ~1/min |
| Onionoo Summary | `https://onionoo.torproject.org/summary` | ~1/min |

### Ports Used

| Port | Service |
|------|---------|
| 8501 | Streamlit Dashboard |
| 9051 | TOR Control Port |
| 9001 | TOR OR Port (typical) |

---

## 📁 Project Structure

```
tor_classifier/
├── app.py                      # Main Streamlit dashboard
├── requirements.txt            # Python dependencies
├── PROJECT_DETAILS.md          # This documentation
│
├── core/                       # Core components
│   ├── stream_ingester.py      # Packet capture
│   ├── flow_extractor.py       # Flow aggregation
│   ├── consensus_fetcher.py    # Onionoo API
│   ├── entry_guard_analyzer.py # Guard detection
│   ├── circuit_monitor.py      # TOR circuit monitoring
│   ├── ja3_fingerprinter.py    # TLS fingerprinting
│   ├── alert_system.py         # Real-time alerts
│   └── tor_consensus_updater.py# Background consensus refresh
│
├── analysis/                   # Analysis modules
│   ├── origin_tracer.py        # Origin IP tracing
│   ├── correlation_attack.py   # Static correlation
│   ├── realtime_correlation.py # Live correlation
│   ├── website_fingerprinter.py# Website identification
│   ├── activity_fingerprinter.py# Activity classification
│   ├── burst_correlator.py     # Burst analysis
│   └── global_monitor.py       # Network monitoring
│
├── models/                     # ML models
│   └── deep_classifier.py      # Neural network classifier
│
├── utils/                      # Utilities
│   └── forensic_report_generator.py # Report export
│
├── reports/                    # Generated reports
└── alerts/                     # Alert logs
```

---

*Documentation generated for RT-TTA Cybersecurity Hackathon 2024*
