# Sentinel.net

Sentinel.net is a multi-agentic Python-based network security system for Windows, designed to capture, analyze, detect, and respond to network incidents. It combines packet sniffing, AI-based detection, and automated incident response, with future plans for granular agent scope control using Descope.

## Features

- **Sniffer:**

  - Interactive network interface selection
  - TCP/UDP packet capture using Scapy
  - Timestamped PCAP file storage
  - Packet parsing and flow record generation

- **AI-Based Detector:**

  - Extracts flow features from captured packets
  - Integrates machine learning models (e.g., Isolation Forest) to identify suspicious or malicious network activity
  - Real-time and batch analysis
  - Alert generation and metrics tracking

- **Incident Responder Agents:** _(Planned)_

  - Automated response to detected incidents
  - Modular agent architecture for custom response strategies

- **Utils:**

  - Utility functions for progress bars, interface selection, and more

- **Scope Limitation:** _(Planned)_
  - Integration with [Descope](https://www.descope.com/) to restrict agent scopes and permissions for enhanced security

## Directory Structure

```
sentinel.net/
│
├── config.py                 # Global constants and paths
│
├── sniffer/                  # Packet capture & flow building
│ ├── capture.py
│ ├── if_manager.py
│ ├── parser.py
│ ├── capture_logs/           # PCAPs stored here
│ └── parsed_logs/
│
├── detector/                 # Feature extraction & anomaly detection
│ ├── metrics.py
│ ├── feature_builder.py
│ ├── detector.py
│ ├── realtime.py
│ ├── features/               # Feature files
│ ├── models/                 # Trained Isolation Forest models
│ └── alerts/                 # Detection alerts
│
├── utils/ # Helpers
│ ├── chooser.py              # Interactive file selector
│ ├── progress.py             # CLI progress bars
│
├── flow_records/             # JSON/JSONL flow records
├── responder/                # Planned responder agent
└── tests/                    # Unit tests
```

## Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/yourusername/sentinel.net.git
   cd sentinel.net
   ```

2. **Create a virtual environment (Recommended):**
   ```sh
   python -m venv venv
   venv\Scripts\activate      # Windows
   ```
3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
4. **Platform Setup:**
   Install [NPcap](https://npcap.com/)

## Usage

### Sniffer

1. **Run the sniffer:**

   ```sh
   python -m sniffer.capture
   ```

   - Select a network interface when prompted.
   - Captured packets are saved in `sniffer/capture_logs/`.

2. **Parse packets and generate flow records:**
   ```sh
   python -m sniffer.parser
   ```
   - Select a PCAP file to analyze.
   - Flow records are saved in `flow_records/`.

### Detector

1. **Build Features:**

   ```sh
   python -m detector.feature_builder
   ```

   - Uses flow records to build features.
   - Features are saved in `detector/features/`.

2. **Train the detector:**

   ```sh
   python -m detector.detector train
   ```

   - Uses flow features to train the model.
   - Alerts are saved in `detector/models/`.

3. **Run the detector:**

   ```sh
   python -m detector.detector score
   ```

   - Uses flow features and trained model to detect anomalies.
   - Alerts are saved in `detector/alerts/`.

### Responder

- **Responder modules** will be available in future releases.

## Requirements

- Python 3.11+
- [Scapy](https://scapy.net/)
- [psutil](https://github.com/giampaolo/psutil)
- [tabulate](https://pypi.org/project/tabulate/)
- [pytest](https://pytest.org/)
- [Numpy] (https://numpy.org/)
- [Scikit-learn] (https://scikit-learn.org/stable/)
- [Joblib] (https://joblib.readthedocs.io/)
- [Humanize] (https://pypi.org/project/humanize/)

## Future Prospects

- Responder Agent: automatic blocking/quarantine actions.
- GUI/Dashboard: visualize flows, features, and alerts in real time.
- Improved Models: protocol-specific Isolation Forests, or deep learning models.
- Threshold Calibration: save percentile thresholds alongside models.
- Integration: export alerts into ELK/Grafana/Prometheus pipelines.
- Optimization: multiprocessing parsers, GPU-accelerated training, sampling strategies.
- Cross-Platform Support: any operating system can use.

## Notes

- Output and test directories are git-ignored.
- Future releases will integrate Descope for agent scope management.
