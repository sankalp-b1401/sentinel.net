# config.py
from __future__ import annotations
from pathlib import Path

# Root-relative dirs
ROOT_DIR = Path(__file__).resolve().parent
CAPTURE_DIR = ROOT_DIR / "sniffer" / "capture_logs"
PARSED_DIR = ROOT_DIR / "sniffer" / "parsed_logs"
FLOW_RECORD_DIR = ROOT_DIR / "flow_records"
FEATURES_DIR = ROOT_DIR / "detector" / "features"
ALERTS_DIR = ROOT_DIR / "detector" / "alerts"
MODELS_DIR = ROOT_DIR / "detector" / "models"

# Sniffer / Parser
BPF_FILTER = "tcp or udp"
FLOW_EXPIRATION_SECONDS = 30
MAX_QUEUE_SIZE = 50_000  # packets
JSON_INDENT = 2

# Real-time detector defaults
MODEL_FILENAME = "iforest_v1.joblib"
ALERTS_FILENAME = "realtime_alerts.jsonl"
TOPK_STREAM_LOG = 0  # 0 = log all anomalies predicted by IF; else show top-N only
