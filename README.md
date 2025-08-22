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
├── sniffer/
│   ├── capture.py         # Packet capture logic
│   ├── if_manager.py      # Interface selection
│   ├── parser.py          # Packet parsing and flow record generation
│   ├── capture_logs/      # Saved PCAP files
│   ├── parsed_logs/       # Per-packet JSON (optional)
│
├── detector/              # (Planned) AI-based detection logic
│
├── responder/             # (Planned) Incident response agents
│
├── flow_records/          # Output flow record JSON files
│
├── tests/                 # Unit tests
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
