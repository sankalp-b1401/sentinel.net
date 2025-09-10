#!/usr/bin/env python3
"""
Detector HTTP server: receives batches of flow records (JSON array) from sniffer.

Enhancements:
 - Integrates with ui.py for consistent colored/status output.
 - Graceful shutdown on SIGINT/SIGTERM (Ctrl+C) with UI message.
 - Attempts to stop the worker cleanly if the worker exposes stop() / join().
 - Model selection displays ls-style table and filters non-model files.
 - Adds session finalize/status endpoints secured with JWT scope checks.
 - Validates JWKS & audience configuration at startup (to catch misconfig / clock skew).
"""
from __future__ import annotations
import os
import sys
import signal
import logging
from pathlib import Path
from queue import Queue
from datetime import datetime
import json
import argparse
from typing import Optional

# Flask
from flask import Flask, request, jsonify, make_response

# ui helpers (centralized styling + prompts)
from ui import (
    info,
    warn,
    err,
    ok,
    prompt_hint_and_input,
    human_size,
    fmt_mtime_ls,
)

# auth verification (expects verify_token_and_scope to be implemented)
from auth.jwk_verify import verify_token_and_scope, validate_jwks_and_audience

# worker loader (start_worker should start background processing of work_q)
from detector.queue_worker import start_worker

# try to import config values; use sane defaults if missing
try:
    from config import MODELS_DIR, MODEL_FILENAME, INBOX_DIR, ALERTS_DIR, ALERTS_FILENAME
    # auth-related config used for validation
    from config import DESCOPE_JWKS_URL, SERVICE_AUDIENCE, SERVICE_JWT

except Exception:
    MODELS_DIR = Path("detector/models")
    MODEL_FILENAME = "iforest_v1.joblib"
    INBOX_DIR = Path("detector/inbox")
    ALERTS_DIR = Path("detector/alerts")
    ALERTS_FILENAME = "http_batch_alerts.jsonl"
    ALLOWED_SNIFFER_IDS = set()
    DESCOPE_JWKS_URL = ""
    SERVICE_AUDIENCE = ""
    SERVICE_JWT = None

# ensure paths are Path objects
MODELS_DIR = Path(MODELS_DIR)
INBOX_DIR = Path(INBOX_DIR)
ALERTS_DIR = Path(ALERTS_DIR)
JOBS_DIR = Path("detector") / "jobs"
STATUS_DIR = Path("detector") / "status"
ALERTS_DIR.mkdir(parents=True, exist_ok=True)
INBOX_DIR.mkdir(parents=True, exist_ok=True)
JOBS_DIR.mkdir(parents=True, exist_ok=True)
STATUS_DIR.mkdir(parents=True, exist_ok=True)

# Logging (keep standard logging, but also emit ui-style notices)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("detector.server_http")

# queue & flask app
work_q = Queue(maxsize=2000)
app = Flask(__name__)

# global worker reference (set when start_worker is called)
_worker_obj = None

# graceful shutdown state
_shutdown_requested = False


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


def _require_token_and_scope(allowed_scopes: list[str]):
    """
    Extract Authorization header, verify token via JWKS, and ensure one of allowed_scopes is present.
    Returns decoded claims dict on success, or a Flask response (make_response) on failure.
    """
    auth = request.headers.get("Authorization", "")
    if not auth or not auth.startswith("Bearer "):
        return make_response(("missing Authorization Bearer token", 401))
    token = auth.split(" ", 1)[1].strip()
    try:
        # verify signature, audience, expiry (no scope check here)
        claims = verify_token_and_scope(token)
    except Exception as e:
        return make_response((f"unauthorized: {e}", 401))

    # normalize scope claim (could be str or list)
    sc = claims.get("scope", "")
    scopes = set()
    if isinstance(sc, str):
        scopes = set(sc.split())
    elif isinstance(sc, (list, tuple)):
        scopes = set(sc)
    # check allowed scopes intersection
    if not any(s in scopes for s in allowed_scopes):
        return make_response(("forbidden: missing required scope", 403))

    # success: return claims (so caller can use them)
    return claims


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

    # 4) parse JSON
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        log.warning("invalid JSON payload: %s", e)
        return ("invalid JSON payload", 400)

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

    # 5) persist this batch to inbox as one file (one session per file if session_id provided)
    session_id = None
    # payload may be an object with 'flows' (we parsed into 'flows' above) and 'meta'
    if isinstance(payload, dict):
        session_id = payload.get("session_id") or (meta.get("session_id") if isinstance(meta, dict) else None)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    seq = int(datetime.utcnow().microsecond // 1000)  # ms-ish sequence to avoid collisions
    filename = f"batch_{ts}_{seq}.jsonl"

    # Save under session subdir if session_id present
    try:
        if session_id:
            session_dir = INBOX_DIR / str(session_id)
            session_dir.mkdir(parents=True, exist_ok=True)
            out_path = session_dir / filename
        else:
            out_path = INBOX_DIR / filename

        with out_path.open("w", encoding="utf-8") as fh:
            if meta:
                fh.write(json.dumps({"_meta": meta}) + "\n")
            for f in flows:
                fh.write(json.dumps(f) + "\n")
    except Exception as e:
        log.exception("failed to write inbox file: %s", e)
        return ("failed to save batch", 500)

    # 6) enqueue batch for processing (worker expects a job dict with path)
    try:
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

    log.info("accepted batch of %d flows from agent=%s saved=%s job=%s", len(flows), "sniffer", out_path, job["batch_id"])
    info(f"[-] accepted batch of {len(flows)} flows from agent=sniffer saved={out_path} job={job['batch_id']}")
    return jsonify({"accepted": len(flows), "saved": str(out_path), "job_id": job["batch_id"]}), 202


@app.route("/api/v1/sessions/<session_id>/finalize", methods=["POST"])
def session_finalize(session_id):
    """
    Client FIN: mark session as queued for processing. Requires 'sniffer:push' scope.
    """
    # require token with write scope
    creds = _require_token_and_scope(["sniffer:push"])
    if not isinstance(creds, dict):
        # _require_token_and_scope returns a Flask response on failure
        return creds

    sid = str(session_id)
    job_path = JOBS_DIR / f"session_{sid}.job"
    status_path = STATUS_DIR / f"session_{sid}.json"
    if job_path.exists():
        return jsonify({"session_id": sid, "status": "queued"}), 202
    try:
        job = {"session_id": sid, "queued_at": datetime.utcnow().timestamp(), "requested_by": creds.get("sub")}
        job_path.write_text(json.dumps(job), encoding="utf-8")
        status_path.write_text(json.dumps({"session_id": sid, "status": "queued", "queued_at": job["queued_at"]}), encoding="utf-8")
        info(f"[-] session queued: {sid}")
        return jsonify({"session_id": sid, "status": "queued"}), 202
    except Exception as e:
        log.exception("failed to create session job: %s", e)
        return (f"failed to queue session: {e}", 500)


@app.route("/api/v1/sessions/<session_id>/status", methods=["GET"])
def session_status(session_id):
    """
    Return session status JSON. Accepts tokens with either 'sniffer:read' or 'sniffer:push'.
    """
    creds = _require_token_and_scope(["sniffer:read", "sniffer:push"])
    if not isinstance(creds, dict):
        return creds

    sid = str(session_id)
    status_path = STATUS_DIR / f"session_{sid}.json"
    if not status_path.exists():
        return jsonify({"session_id": sid, "status": "pending"}), 200
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
        return jsonify(data), 200
    except Exception as e:
        log.exception("failed to read session status: %s", e)
        return (f"failed to read status: {e}", 500)


def _is_model_file(p: Path) -> bool:
    """Decide whether a file should be presented as a model to the user.

    Heuristics: include typical model extensions (joblib, pkl) but exclude files
    that contain substrings indicating scalers/metadata/preproc artifacts.
    """
    if not p.is_file():
        return False
    name = p.name.lower()
    # allowed extensions
    if not any(name.endswith(ext) for ext in ('.joblib', '.pkl', '.pickle')):
        return False
    # exclude files that look like scalers, meta, params, vocab, vectorizer, preproc
    excluded_subs = ('scaler', 'scale', 'meta', 'params', 'vector', 'vocab', 'preproc', 'preprocess', 'encoder', 'label')
    if any(sub in name for sub in excluded_subs):
        return False
    return True


def _choose_model_interactive(models_dir: Path) -> Path | None:
    """
    Prompt the user to pick a model file from models_dir using ui.prompt_hint_and_input.
    Returns Path or None if user aborted. Only displays files that pass _is_model_file().
    Displays them in an ls-style table.
    """
    models_dir = Path(models_dir)
    if not models_dir.exists():
        err(f"[-] models directory not found: {models_dir}")
        return None

    # gather only candidate model files
    candidates = [p for p in sorted(models_dir.iterdir()) if _is_model_file(p)]
    if not candidates:
        err(f"[-] no model files found in {models_dir} (filtered by heuristics)")
        return None

    # Prepare ls-like table: No., Size, Modified, Name
    idx_w = 4
    size_w = 8
    date_w = 12
    name_w = max(30, max(len(p.name) for p in candidates))
    sep = "  "

    hdr = f"{'No.'.ljust(idx_w)}{sep}{'Size'.rjust(size_w)}{sep}{'Modified'.ljust(date_w)}{sep}Name"
    info("[-] Available models:")
    print("\n" + hdr)
    print('-' * (idx_w + size_w + date_w + name_w + len(sep) + 6))

    for i, p in enumerate(candidates, start=1):
        try:
            size = human_size(p.stat().st_size)
        except Exception:
            size = "-"
        try:
            mtime = fmt_mtime_ls(p)
        except Exception:
            mtime = "-"
        print(f"{str(i).ljust(idx_w)}{sep}{size.rjust(size_w)}{sep}{mtime.ljust(date_w)}{sep}{p.name}")

    print('\n0) Cancel / exit')

    while True:
        sel_raw = prompt_hint_and_input("[?]", f"Select model [0-{len(candidates)}]")
        if sel_raw == "":
            print("[-] No selection. Cancelled.")
            return None
        try:
            sel = int(sel_raw)
            if sel == 0:
                return None
            if 1 <= sel <= len(candidates):
                return candidates[sel - 1]
            print("[-] Invalid selection; try again.")
        except ValueError:
            print("[-] Enter a number corresponding to the model index.")


def _stop_worker_if_possible(worker) -> None:
    """Best-effort attempt to stop the worker if it exposes stop()/join()"""
    if worker is None:
        return
    try:
        # try common patterns
        if hasattr(worker, "stop") and callable(worker.stop):
            try:
                info("[-] stopping worker (stop)...")
                worker.stop()
            except Exception:
                pass
        if hasattr(worker, "join") and callable(worker.join):
            try:
                info("[-] waiting for worker to finish (join, timeout=5s)...")
                worker.join(timeout=5)
            except Exception:
                pass
    except Exception:
        # swallow any error to avoid interfering with shutdown
        pass


def _signal_handler(signum, frame):
    """Signal handler for SIGINT / SIGTERM — prints UI message and attempts graceful shutdown."""
    global _shutdown_requested, _worker_obj
    if _shutdown_requested:
        # second signal -> force exit
        try:
            info("[-] Forced shutdown requested. Exiting immediately.")
        except Exception:
            pass
        os._exit(1)

    _shutdown_requested = True
    try:
        info("[-] Shutdown requested (Ctrl+C). Stopping server...")
    except Exception:
        pass

    # Try to stop worker gracefully
    try:
        _stop_worker_if_possible(_worker_obj)
    except Exception:
        pass

    # Final exit
    try:
        info("[-] Exiting now.")
    except Exception:
        pass
    # Use os._exit to avoid problems if Flask internals swallow KeyboardInterrupt
    os._exit(0)


def run_server(model_path: str | Path = None, host: str = "0.0.0.0", port: int = 8443,
               no_interactive: bool = False, auth_check: bool = True):
    """Start the detector server. Prompts for model if not provided (unless no_interactive)."""

    global MODELS_DIR, _worker_obj

    model_path_arg = Path(model_path) if model_path else None

    if model_path_arg:
        if not model_path_arg.exists():
            raise FileNotFoundError(f"model not found at {model_path_arg}")
        selected_model = model_path_arg
    else:
        if no_interactive:
            raise RuntimeError("No model provided and interactive selection disabled (--no-interactive).")
        info("[-] Detector server: model selection")
        pick = _choose_model_interactive(MODELS_DIR)
        if pick is None:
            err("[-] No model selected. Aborting server startup.")
            sys.exit(1)
        selected_model = pick

    # AUTH CONFIG VALIDATION (optional)
    if auth_check:
        try:
            # Use SERVICE_JWT (if set) as sample token to decode; otherwise skip token decode but verify JWKS reachable
            sample_token = SERVICE_JWT or None
            info("[-] validating JWKS & audience configuration...")
            res = validate_jwks_and_audience(DESCOPE_JWKS_URL, SERVICE_AUDIENCE, sample_token=sample_token, max_skew_seconds=30)
            info(f"[-] JWKS reachable (keys={res.get('key_count',0)})")
            skew = res.get("clock_skew_seconds")
            if skew is not None and res.get("clock_skew_warning", False):
                warn(f"[-] clock skew detected between detector host and JWKS server ≈ {skew:.1f}s. This may cause 'iat/nbf' JWT rejections. Sync system clock with NTP.")
            if res.get("token_checked"):
                if not res.get("token_audience_ok", False):
                    raise Exception("sample token audience did not match configured SERVICE_AUDIENCE")
                info("[-] sample service token decoded and audience OK")
        except Exception as e:
            err(f"[-] Auth configuration validation failed: {e}")
            err("[-] Aborting server startup to avoid running with broken auth configuration. If you want to bypass this check, run with --no-auth-check (not recommended).")
            sys.exit(1)

    # READY: start worker and server
    try:
        info(f"[-] starting worker with model {selected_model}")
        # start_worker may return a thread/worker object; capture it for graceful shutdown attempts
        _worker_obj = start_worker(work_q, model_path=str(selected_model))
        ok(f"[-] worker started (model={selected_model.name})")
    except Exception as e:
        err(f"[-] failed to start worker with model {selected_model}: {e}")
        raise

    # register signal handlers so Ctrl+C while server is listening is handled
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    cert = Path("server.crt")
    key = Path("server.key")
    try:
        if cert.exists() and key.exists():
            info(f"[-] starting HTTPS server on {host}:{port}")
            app.run(host=host, port=port, ssl_context=(str(cert), str(key)))
        else:
            warn(f"[-] server.crt/server.key not found — starting HTTP (insecure, dev only) on {host}:{port}")
            app.run(host=host, port=port)
    except SystemExit:
        # allow normal sys.exit() to propagate
        raise
    except Exception as e:
        # If an exception happens here, we still want to try to stop worker gracefully
        err(f"[-] Server error: {e}")
        try:
            _stop_worker_if_possible(_worker_obj)
        except Exception:
            pass
        raise


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Detector HTTP server (requires model).")
    ap.add_argument("--model", help="path to model file", default=None)
    ap.add_argument("--host", help="host", default="127.0.0.1")
    ap.add_argument("--port", help="port", type=int, default=8443)
    ap.add_argument("--no-interactive", help="do not prompt for model selection; require --model", action="store_true")
    ap.add_argument("--no-auth-check", help="skip JWKS / audience validation at startup (dangerous)", action="store_true")
    args = ap.parse_args()

    try:
        run_server(model_path=args.model, host=args.host, port=args.port, no_interactive=args.no_interactive, auth_check=(not args.no_auth_check))
    except KeyboardInterrupt:
        # Top-level intercept for Ctrl+C during model selection or startup
        print("/n")
        info("[-] Program ended by user (Ctrl+C). Exiting.")
        sys.exit(0)
    except SystemExit:
        raise
    except Exception as e:
        print("/n")
        err(f"[-] Unhandled error during server startup: {e}")
        sys.exit(1)
