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
├── sniffer/
│   ├── capture.py
│   ├── if_manager.py
│   ├── parser.py
│   ├── capture_logs/
│   ├── parsed_logs/
│
├── detector/
│   ├── __init__.py
│   ├── detector.py
│   ├── feature_builder.py
│   ├── metrics.py
│   ├── real_time.py
│   ├── alerts/
│   ├── features/
│   └── models/
│
├── utils/
│   ├── __init__.py
│   ├── chooser.py
│   ├── progress.py
│
├── responder/          # (Planned)
│
├── flow_records/
│
├── tests/
│
├── requirements.txt
└── README.md
```

## Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/yourusername/sentinel.net.git
   cd sentinel.net
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

## Usage

### Sniffer

1. **Run the sniffer:**

   ```sh
   python sniffer/capture.py
   ```

   - Select a network interface when prompted.
   - Captured packets are saved in `sniffer/capture_logs/`.

2. **Parse packets and generate flow records:**
   ```sh
   python sniffer/parser.py
   ```
   - Select a PCAP file to analyze.
   - Flow records are saved in `flow_records/`.

### Detector

1. **Run the detector:**
   ```sh
   python detector/detector.py
   ```
   - Uses flow features and trained models to detect anomalies.
   - Alerts are saved in `detector/alerts/`.

### Responder

- **Responder modules** will be available in future releases.

## Requirements

- Python 3.11+
- [Scapy](https://scapy.net/)
- [psutil](https://github.com/giampaolo/psutil)
- [tabulate](https://pypi.org/project/tabulate/)
- [pytest](https://pytest.org/)
- Windows OS with NPCAP installed

## Notes

- Output and test directories are git-ignored.
- Future releases will integrate Descope for agent scope management.

## License

MIT License (add your
