# detector/server_http.py
"""
Detector HTTP server: receives batches of flow records (JSON array) from sniffer.
Expects header: Authorization: Bearer <token>
Verifies token via auth.jwk_verify.verify_token_and_scope(...)
Saves each incoming POST as detector/inbox/batch_YYYYmmdd_HHMMSS.jsonl
Enqueues the flows to the worker queue (detector.queue_worker.start_worker).
"""

from __future__ import annotations
import os
import logging
from pathlib import Path
from queue import Queue
from datetime import datetime
import json
import argparse

from flask import Flask, request, jsonify

# auth verification (uses the jwk_verify we placed under detector/auth/)
from auth.jwk_verify import verify_token_and_scope

# worker loader
from detector.queue_worker import start_worker

# try to import config values; use sane defaults if missing
try:
    from config import MODELS_DIR, MODEL_FILENAME, INBOX_DIR, ALERTS_DIR, ALERTS_FILENAME, ALLOWED_SNIFFER_IDS
except Exception:
    # defaults if user hasn't set config fully
    MODELS_DIR = Path("detector/models")
    MODEL_FILENAME = "iforest_v1.joblib"
    INBOX_DIR = Path("detector/inbox")
    ALERTS_DIR = Path("detector/alerts")
    ALERTS_FILENAME = "http_batch_alerts.jsonl"
    ALLOWED_SNIFFER_IDS = set()

# ensure paths are Path objects
MODELS_DIR = Path(MODELS_DIR)
INBOX_DIR = Path(INBOX_DIR)
ALERTS_DIR = Path(ALERTS_DIR)
ALERTS_DIR.mkdir(parents=True, exist_ok=True)
INBOX_DIR.mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("detector.server_http")

# queue & flask app
work_q = Queue(maxsize=2000)
app = Flask(__name__)

@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/api/v1/flows", methods=["POST"])
def ingest_flows():
    # 1) Authorization header
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return ("missing token", 401)
    token = auth.split(" ", 1)[1]

    # 2) verify token + required scope
    try:
        claims = verify_token_and_scope(token, required_scope="sniffer:push")
    except Exception as e:
        log.warning("token verification failed: %s", e)
        return (f"unauthorized: {e}", 401)

    # 3) optional identity whitelist
    agent_id = ""
    try:
        if isinstance(claims, dict):
            agent_id = claims.get("sub") or claims.get("azp") or claims.get("client_id") or claims.get("iss") or ""
    except Exception:
        agent_id = ""

    if ALLOWED_SNIFFER_IDS:
        # allow ALLOWED_SNIFFER_IDS as iterable of strings or set in config
        allowed = set(ALLOWED_SNIFFER_IDS) if not isinstance(ALLOWED_SNIFFER_IDS, set) else ALLOWED_SNIFFER_IDS
        if agent_id and agent_id not in allowed:
            log.warning("agent '%s' not in allowed list", agent_id)
            return (f"agent not allowed: {agent_id}", 403)

    # 4) parse JSON
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        log.warning("invalid JSON payload: %s", e)
        return ("invalid JSON payload", 400)

    # support either list-of-flows or {"flows": [...], "meta": {...}}
    if isinstance(payload, dict) and "flows" in payload and isinstance(payload["flows"], list):
        flows = payload["flows"]
        meta = payload.get("meta", {})
    elif isinstance(payload, list):
        flows = payload
        meta = {}
    else:
        return ("expected a JSON array of flows or an object with 'flows' key", 400)

    if not isinstance(flows, list):
        return ("expected list of flow objects", 400)

    # 5) persist this batch to inbox as one file (one session per file)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"batch_{ts}.jsonl"
    out_path = INBOX_DIR / filename
    try:
        with out_path.open("w", encoding="utf-8") as fh:
            # write optional header meta as a JSON object first (non-flow metadata)
            if meta:
                fh.write(json.dumps({"_meta": meta}) + "\n")
            for f in flows:
                fh.write(json.dumps(f) + "\n")
    except Exception as e:
        log.exception("failed to write inbox file: %s", e)
        return ("failed to save batch", 500)

    # 6) enqueue batch for processing (worker expects a job dict with path)
    try:
        # build job dict: worker will open path and process the batch file
        job = {
            "batch_id": filename.replace(".jsonl", ""),
            "path": str(out_path),
            "meta": meta,
            "claims": claims if isinstance(claims, dict) else {}
        }
        work_q.put_nowait(job)
    except Exception as e:
        log.error("work queue full or put error: %s", e)
        return ("queue full", 503)

    log.info("accepted batch of %d flows from agent=%s saved=%s job=%s", len(flows), agent_id or "unknown", out_path, job["batch_id"])
    return jsonify({"accepted": len(flows), "saved": str(out_path), "job_id": job["batch_id"]}), 202

def _choose_model_interactive(models_dir: Path) -> Path | None:
    """
    Prompt the user to pick a model file from models_dir.
    Returns Path or None if user aborted.
    """
    models_dir = Path(models_dir)
    if not models_dir.exists():
        print(f"[error] models directory not found: {models_dir}")
        return None

    files = sorted(models_dir.glob("*.joblib"))
    if not files:
        print(f"[error] no .joblib model files found in {models_dir}")
        return None

    print("\nAvailable models:")
    for i, f in enumerate(files, start=1):
        try:
            size_kb = f.stat().st_size / 1024.0
        except Exception:
            size_kb = 0.0
        print(f"  {i}. {f.name} ({size_kb:.1f} KB)")
    print("  0. Cancel / exit\n")

    while True:
        try:
            choice = input(f"Select model [0-{len(files)}] (0=cancel): ").strip()
            if choice == "":
                print("No selection. Cancelled.")
                return None
            idx = int(choice)
            if idx == 0:
                return None
            if 1 <= idx <= len(files):
                return files[idx - 1]
            print("Invalid selection; try again.")
        except ValueError:
            print("Enter a number corresponding to the model index.")

def run_server(model_path: str | Path = None, host: str = "0.0.0.0", port: int = 8443, no_interactive: bool = False):
    """
    Start the detector server. If model_path is None and no_interactive is False,
    prompt the user to select a model from MODELS_DIR. If no_interactive is True
    and model_path not given, exit with error.
    """
    global MODELS_DIR

    # Convert to Path
    model_path_arg = Path(model_path) if model_path else None

    # If model provided explicitly, validate
    if model_path_arg:
        if not model_path_arg.exists():
            raise FileNotFoundError(f"model not found at {model_path_arg}")
        selected_model = model_path_arg
    else:
        # No model arg given
        if no_interactive:
            raise RuntimeError("No model provided and interactive selection disabled (--no-interactive).")
        # interactive pick
        print("\n*** Detector server: model selection ***")
        pick = _choose_model_interactive(MODELS_DIR)
        if pick is None:
            print("No model selected. Aborting server startup.")
            sys.exit(1)
        selected_model = pick

    # READY: start worker and server
    try:
        print(f"[info] starting worker with model {selected_model}")
        start_worker(work_q, model_path=str(selected_model))
    except Exception as e:
        print(f"[error] failed to start worker with model {selected_model}: {e}")
        raise

    cert = Path("server.crt")
    key = Path("server.key")
    if cert.exists() and key.exists():
        print(f"[info] starting HTTPS server on {host}:{port}")
        app.run(host=host, port=port, ssl_context=(str(cert), str(key)))
    else:
        print(f"[warning] server.crt/server.key not found — starting HTTP (insecure, dev only) on {host}:{port}")
        app.run(host=host, port=port)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Detector HTTP server (requires model).")
    ap.add_argument("--model", help="path to model file", default=None)
    ap.add_argument("--host", help="host", default="127.0.0.1")
    ap.add_argument("--port", help="port", type=int, default=8443)
    ap.add_argument("--no-interactive", help="do not prompt for model selection; require --model", action="store_true")
    args = ap.parse_args()
    run_server(model_path=args.model, host=args.host, port=args.port, no_interactive=args.no_interactive)
