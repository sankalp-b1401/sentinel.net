# config.py
from __future__ import annotations
from pathlib import Path
from os import getenv

# load .env if present
try:
    from dotenv import load_dotenv
    # load_dotenv looks for a .env file in the project root and loads environment overrides
    load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
except ImportError:
    # If python-dotenv isn't installed we silently continue — envvars may still be set externally.
    pass

# Root-related directories used across the project
ROOT_DIR = Path(__file__).resolve().parent
CAPTURE_DIR = ROOT_DIR / "sniffer" / "capture_logs"
PARSED_DIR = ROOT_DIR / "sniffer" / "parsed_logs"
FLOW_RECORD_DIR = ROOT_DIR / "flow_records"
FEATURES_DIR = ROOT_DIR / "detector" / "features"
ALERTS_DIR = ROOT_DIR / "detector" / "alerts"
MODELS_DIR = ROOT_DIR / "detector" / "models"
INBOX_DIR = ROOT_DIR / "detector" / "inbox"
STATUS_DIR = ROOT_DIR / "detector" / "status"
JOBS_DIR = ROOT_DIR / "detector" / "jobs"

# -----------------------
# Sniffer / Parser defaults
# -----------------------
# DEFAULT_BATCH_SIZE determines how many flow records are grouped before sending
DEFAULT_BATCH_SIZE = 128
# BPF_FILTER is used by scapy/sniff to reduce capture noise to TCP/UDP only
BPF_FILTER = "tcp or udp"
# FLOW_EXPIRATION_SECONDS defines how long a flow can be idle before we close it and emit it
FLOW_EXPIRATION_SECONDS = 30
# MAX_QUEUE_SIZE guards against OOM when streaming packets into an in-memory queue
MAX_QUEUE_SIZE = 50_000  # packets
# JSON_INDENT used when writing JSON for readability
JSON_INDENT = 2

# Real-time detector defaults and artifact names
MODEL_FILENAME = "iforest_v1.joblib"
ALERTS_FILENAME = "realtime_alerts.jsonl"
# TOPK_STREAM_LOG: 0 means log all anomalies; >0 will limit printed anomalies to top-N
TOPK_STREAM_LOG = 0  # 0 = log all anomalies predicted by IF; else show top-N only

# -----------------------
# Descope / Auth settings
# -----------------------
# JWKS URL used by detector to fetch public keys for JWT verification.
# Example: "https://<tenant>.descope.com/.well-known/jwks.json"
DESCOPE_JWKS_URL = getenv("DESCOPE_JWKS_URL", "")
DESCOPE_DISCOVERY_URL = getenv("DESCOPE_DISCOVERY_URL", "")

# Option A: set SERVICE_JWT to a pre-generated long-lived token for local dev/testing
SERVICE_JWT = getenv("SERVICE_JWT", "")

# Option B: mint short-lived service tokens via client-credentials against a secure endpoint.
DESCOPE_TOKEN_ENDPOINT = getenv("DESCOPE_TOKEN_ENDPOINT", "")
DESCOPE_CLIENT_ID = getenv("DESCOPE_CLIENT_ID", "")
DESCOPE_CLIENT_SECRET = getenv("DESCOPE_CLIENT_SECRET", "")

# Required audience to validate incoming service tokens (set to your inbound-app audience)
SERVICE_AUDIENCE = getenv("SERVICE_AUDIENCE", "")

# Detector API URL where sniffer will post flows when AUTH_TRANSPORT == "http"
DETECTOR_URL = getenv("DETECTOR_URL", "https://127.0.0.1:8443")

# Transport mechanism selection: "http" uses Descope-backed HTTP transport; "unix" or others may exist
AUTH_TRANSPORT = getenv("AUTH_TRANSPORT", "http")  # "unix" or "http"
TRANSPORT_TIMEOUT = 15

# Model & artifacts directories are defined above (MODELS_DIR, FEATURES_DIR etc).
# Keep configuration centralized so other modules import from here.
