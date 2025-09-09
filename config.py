# config.py
from __future__ import annotations
from pathlib import Path
from os import getenv

# load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
except ImportError:
    # silently skip if python-dotenv not installed
    pass

# Root-relative dirs
ROOT_DIR = Path(__file__).resolve().parent
CAPTURE_DIR = ROOT_DIR / "sniffer" / "capture_logs"
PARSED_DIR = ROOT_DIR / "sniffer" / "parsed_logs"
FLOW_RECORD_DIR = ROOT_DIR / "flow_records"
FEATURES_DIR = ROOT_DIR / "detector" / "features"
ALERTS_DIR = ROOT_DIR / "detector" / "alerts"
MODELS_DIR = ROOT_DIR / "detector" / "models"
INBOX_DIR = ROOT_DIR / "detector" / "inbox"
STATUS_DIR = ROOT_DIR / "detector" / "status"

# Sniffer / Parser
DEFAULT_BATCH_SIZE = 128
BPF_FILTER = "tcp or udp"
FLOW_EXPIRATION_SECONDS = 30
MAX_QUEUE_SIZE = 50_000  # packets
JSON_INDENT = 2

# Real-time detector defaults
MODEL_FILENAME = "iforest_v1.joblib"
ALERTS_FILENAME = "realtime_alerts.jsonl"
TOPK_STREAM_LOG = 0  # 0 = log all anomalies predicted by IF; else show top-N only

# -----------------------
# Descope / Auth settings
# -----------------------
# DESCOPE_JWKS_URL: provider JWKS URL used to verify tokens (Descope Inbound App / tenant JWKS)
# Example (replace with your tenant's JWKS URL): "https://<tenant>.descope.com/.well-known/jwks.json"
DESCOPE_JWKS_URL = getenv("DESCOPE_JWKS_URL", "")
DESCOPE_DISCOVERY_URL = getenv("DESCOPE_DISCOVERY_URL", "")
# Option A: use a pre-created service token (for dev/testing) via env var
# export SERVICE_JWT="eyJ...."
SERVICE_JWT = getenv("SERVICE_JWT", "")

# Option B: mint a server token using an API key & an endpoint you control (Descope provides flows)
DESCOPE_TOKEN_ENDPOINT = getenv("DESCOPE_TOKEN_ENDPOINT", "")  # optional (provider-specific)
DESCOPE_CLIENT_ID = getenv("DESCOPE_CLIENT_ID", "")
DESCOPE_CLIENT_SECRET = getenv("DESCOPE_CLIENT_SECRET", "")

# Required audience (set to your inbound-app audience if provided)
SERVICE_AUDIENCE = getenv("SERVICE_AUDIENCE", "")

# Default detector API URL (sniffer will POST here when AUTH_TRANSPORT == "http")
# Change to detector host and port for distributed setup
DETECTOR_URL = getenv("DETECTOR_URL", "https://127.0.0.1:8443")

# Transport choice (set to "http" to use Descope / HTTP mode)
AUTH_TRANSPORT = getenv("AUTH_TRANSPORT", "http")  # "unix" or "http"
TRANSPORT_TIMEOUT = 15

# Model & artifacts (already exist in your config)
# MODELS_DIR, FEATURES_DIR etc are already set above in your config file.