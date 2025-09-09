# Sentinel.net

A multi-agent AI system for **network monitoring and anomaly detection**, built with a sniffer (Agent A) and a detector (Agent B), securely integrated via **Descope authentication**. The project enables capturing, parsing, and analyzing real-time and offline network traffic, generating alerts for anomalous activities while enforcing **scoped, authenticated agent-to-agent communication**.

---

## Team Details

**Team Name:** Skibidi  
**Member:** Sankalp Bansal

---

## Hackathon Theme

**Theme 3:** Secure agent-to-agent communication and trust.  
Descope provides OAuth-based scoped access tokens, ensuring:

- **Agent identity validation** (`sub`, `azp`, `iss` claims)
- **Fine-grained scopes** (e.g., `sniffer:push`, `detector:adm`)
- **Secure API-to-API communication** between the Sniffer and Detector agents

---

## Key Components

- **Sniffer Agent (Agent A):** Captures network packets, converts to flows, and either stores locally or securely streams batches to Detector.
- **Detector Agent (Agent B):** Scores flows using anomaly detection models (Isolation Forest, etc.), generates alerts, and stores results in structured JSON files.
- **Auth Layer (Descope):** Ensures only authenticated, scoped requests pass between Sniffer and Detector.
- **Main Orchestrator:** CLI-based unified entrypoint (`main.py`) that guides the user through capture, parse, batch-send, and scoring.

---

## Tech Stack

- **Python 3.11**
- **Scapy** (packet capture)
- **psutil** (network interface stats)
- **Flask** (detector API server)
- **scikit-learn** (Isolation Forest anomaly detection)
- **Descope** (OAuth provider for agent authentication and scopes)
- **joblib** (model persistence)
- **Nmap** (packet capture driver)

Dependencies are listed in `requirements.txt`.

---

## Project Tree

```plaintext
sentinel.net/
│
├── auth/                     # Authentication (Descope & JWKS verification)
│   ├── descope_client.py
│   ├── jwk_verify.py
│
├── detector/                 # Detector Agent
│   ├── alerts/
│   ├── features/
│   ├── inbox/
│   ├── models/
│   ├── status/
│   ├── detector.py
│   ├── feature_builder.py
│   ├── metrics.py
│   ├── queue_worker.py
│   ├── real_time.py
│   ├── server_http.py
│
├── sniffer/                  # Sniffer Agent
│   ├── capture_logs/
│   ├── batch_sender.py
│   ├── capture.py
│   ├── if_manager.py
│   ├── parser.py
│   ├── sender_worker.py
│   ├── transport_http.py
│
├── utils/                    # Utility functions
│   ├── alert_accuracy_check.py
│   ├── chooser.py
│   ├── progress.py
│
├── flow_records/             # Stored parsed flow files
├── main.py                   # CLI Orchestrator
├── config.py                 # Config loader for .env variables
├── requirements.txt
└── README.md

```

---

## sentinel.net 101

### 1. Clone & Install

```bash
git clone https://github.com/<your-repo>/sentinel.net.git
cd sentinel.net
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 2. Configure Descope

- Create a **Sniffer-Agent Inbound App** and **Detector-Agent Inbound App** in Descope Console.
- Add required scopes (e.g., `sniffer:push`, `detector:adm`).
- Copy **Client ID, Secret, Issuer, JWKS URL, Token URL** into `.env` file in the project root.

Example `.env`:

```env
DESCOPE_CLIENT_ID=xxxxx
DESCOPE_CLIENT_SECRET=xxxxx
DESCOPE_ISSUER=https://api.descope.com/v1/apps/xxxx
DESCOPE_JWKS_URL=https://api.descope.com/v1/apps/xxxx/.well-known/jwks.json
DESCOPE_TOKEN_ENDPOINT=https://api.descope.com/oauth2/v1/apps/token
SERVICE_AUDIENCE=detector-api
```

### 3. Run Detector (Agent B)

```bash
python -m detector.server_http
```

- Interactive model selection will prompt you to choose a trained model.
- Starts API on `127.0.0.1:8443`.

### 4. Run Sniffer (Agent A)

```bash
python main.py
```

- Offers options to **capture packets**, **parse PCAP**, **save flows locally**, or **send flows directly to Detector**.
- Interactive CLI ensures authentication session is established before streaming.

---

## Example Workflow

1. Capture packets:  
   `main.py` → Capture infinite or finite packets.
2. Choose processing:
   - Save flows locally → stored in `flow_records/`.
   - Send flows to detector → securely authenticated batch transfer.
3. Detector scoring:
   - Alerts saved in `detector/alerts/` as JSON.
   - Each batch/session creates a **new alert file**.

---

## Video Link

[Link to demo video will be added here]

---

## What I would do with more time

- Improve AI model performance (better training datasets, ensemble methods).
- Build **GUI dashboards** for visualization.
- Implement an **automated incident responder agent**.
- Optimize token handling for long-lived real-time capture sessions.

---
