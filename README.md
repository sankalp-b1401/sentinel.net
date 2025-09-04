# Sentinel.net

Sentinel.net is a modular Python-based network security toolkit for Windows, designed to capture, analyze, detect, and respond to network incidents. It combines packet sniffing, AI-based detection, and automated incident response, with future plans for granular agent scope control using Descope.

## Features

- **Sniffer Agent:**

  - Interactive network interface selection
  - TCP/UDP packet capture using Scapy
  - Timestamped PCAP file storage
  - Packet parsing and flow record generation

- **Automated Detector Agent:** _(Coming soon)_

  - Integrates machine learning models to identify suspicious or malicious network activity
  - Real-time and batch analysis of captured packets

- **Incident Responder Agent:** _(Coming soon)_

  - Automated response to detected incidents
  - Modular agent architecture for custom response strategies

- **Scope Limitation:** _(Planned)_
  - Integration with [Descope](https://www.descope.com/) to restrict agent scopes and permissions for enhanced security

## Directory Structure

```
sentinel.net/
│
├── config.py               # central paths & constants
│
├── sniffer/
│   ├── if_manager.py       # class InterfaceManager (Windows NPCAP)
│   ├── capture.py          # class PacketCapture (save pcap OR stream)
│   ├── parser.py           # class FlowBuilder (incremental + expiry)
│   ├── capture_logs/
│   └── parsed_logs/
│
├── detector/
│   ├── metrics.py          # (kept functional; added FEATURE_ORDER)
│   ├── detector.py         # class IsolationForestDetector + CLI
│   ├── feature_builder.py  # batch: flow JSON -> features JSON
│   ├── realtime.py         # real-time orchestrator (threads, queues)
│   ├── alerts/
│   ├── features/
│   └── models/
│
├── flow_records/
└── tests/
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

### Detector & Responder

- **Detector and responder modules** will be available in future releases.

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
