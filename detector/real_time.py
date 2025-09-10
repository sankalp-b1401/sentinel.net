# real_time.py
"""
Real-time packet capture -> flow builder -> feature extraction -> anomaly detection

This module provides a small CLI utility and a programmatic `run_realtime` entry
point which captures packets from a network interface (via scapy), builds
bidirectional flows with a FlowBuilder (idle-expiry semantics), converts flow
records to feature vectors (detector.metrics) and scores them with a trained
IsolationForest detector (detector.detector.IsolationForestDetector).

Behaviour change requested by user: the program will now *first prompt the user
to select the model*, then prompt/select the interface to run capture on — and
use that chosen model for scoring.
"""

from __future__ import annotations

import json
import signal
import sys
from pathlib import Path
from queue import Queue, Empty
from threading import Event
from time import time, sleep
from typing import Optional

# application imports (project-local)
from config import (
    MAX_QUEUE_SIZE,
    ALERTS_DIR,
    MODELS_DIR,
    ALERTS_FILENAME,
    MODEL_FILENAME,
    FLOW_EXPIRATION_SECONDS,
)
from sniffer.if_manager import InterfaceManager
from sniffer.capture import PacketCapture
from sniffer.parser import FlowBuilder
from detector.metrics import features_from_record, FEATURE_ORDER
from detector.detector import IsolationForestDetector
from utils.chooser import select_file


def _save_jsonl(obj: dict, path: Path) -> None:
    """Append a dict as a single-line JSON object to path (JSONL).

    - Creates parent directory if needed.
    - Uses append mode to avoid overwriting previous alerts.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, default=str) + "")
    except Exception as e:
        # never crash the realtime loop because of I/O errors; log to stderr.
        print(f"[err] failed to write alert -> {path}: {e}", file=sys.stderr)


def run_realtime(
    model_path: Optional[Path | str] = None,
    iface_name: Optional[str] = None,
    debug: bool = False,
    stop_event: Optional[Event] = None,
) -> None:

    """Main programmatic entry for real-time detection.
    Behavior changed to: select model first (interactive if needed), then
    select interface (interactive if needed). The selected model is loaded and
    used for the rest of the session.
    """

    # choose model first
    if model_path is None:
        # if default exists choose it otherwise prompt
        candidate = Path(MODELS_DIR) / MODEL_FILENAME
        if candidate.exists():
            print(f"[rt] default model found: {candidate}")
            model_path = candidate
        else:
            model_path = None

    if model_path is None:
        # interactive model selection
        try:
            sel = select_file(MODELS_DIR, ["*.joblib"], title="Select model (.joblib) to use for realtime")
            model_path = Path(sel)
        except Exception as e:
            raise RuntimeError(f"failed to select model: {e}")
    else:
        model_path = Path(model_path)

    if not model_path.exists():
        raise RuntimeError(f"model path does not exist: {model_path}")

    # load model
    # robust model loading: support several shapes of saved model files
    # Strategy:
    # 1) Try joblib.load(path). If it returns a wrapper instance (IsolationForestDetector),
    #    try to ensure it exposes a working `score(X)` method or a concrete sklearn `model`.
    # 2) If joblib.load returns a raw sklearn estimator, attach it to a fresh wrapper.
    # 3) If joblib.load fails, fall back to calling the wrapper's `load(path)` which
    #    some older implementations expect.
    from joblib import load as joblib_load
    det = None
    try:
        loaded_obj = joblib_load(str(model_path))
    except Exception as e_joblib:
        # joblib couldn't load the file directly: try using the wrapper.load(path)
        det = IsolationForestDetector()
        try:
            det.load(model_path)
        except Exception as e2:
            raise RuntimeError(f"failed to load model {model_path}: {e_joblib} / {e2}")
    else:
        # joblib.load succeeded
        if isinstance(loaded_obj, IsolationForestDetector):
            det = loaded_obj
            # ensure the wrapper has a working model or score method
            has_model = hasattr(det, "model") and getattr(det, "model") is not None
            has_score = callable(getattr(det, "score", None))

            # try common alternate attribute names that could host the sklearn estimator
            if not has_model:
                for alt in ("model", "estimator", "clf", "isf", "if_model"):
                    if hasattr(det, alt) and getattr(det, alt) is not None:
                        try:
                            det.model = getattr(det, alt)
                            has_model = True
                            break
                        except Exception:
                            pass

            # if still no model but wrapper exposes a `load` method, try calling it
            if not has_model and callable(getattr(det, "load", None)):
                try:
                    det.load(model_path)
                    has_model = hasattr(det, "model") and getattr(det, "model") is not None
                except Exception:
                    pass

            # if wrapper doesn't provide score but has a sklearn estimator attached, create a small adapter
            if not has_score and has_model:
                # attach a compatibility score method that returns (anom_scores, preds)
                def _compat_score(X):
                    # sklearn IsolationForest: decision_function -> higher means more normal
                    # keep the raw decision_function as anomaly_score, and predict gives {1,-1}
                    anom = det.model.decision_function(X)
                    pred = det.model.predict(X)
                    return anom, pred

                det.score = _compat_score
                has_score = True

            if not has_score and not has_model:
                raise RuntimeError(f"loaded IsolationForestDetector from {model_path} has no model or score method")

        else:
            # loaded_obj appears to be a raw sklearn estimator; attach it to wrapper
            det = IsolationForestDetector()
            # if wrapper supports load(path) try that first for backwards compat
            try:
                det.load(model_path)
            except Exception:
                # attach estimator directly
                try:
                    det.model = loaded_obj
                    # create compatibility score method if missing
                    if not callable(getattr(det, "score", None)):
                        def _compat_score(X):
                            anom = det.model.decision_function(X)
                            pred = det.model.predict(X)
                            return anom, pred

                        det.score = _compat_score
                except Exception as e3:
                    raise RuntimeError(f"failed to attach loaded model object: {e3}")

    # choose interface after model is loaded
    if iface_name is None:
        try:
            iface = InterfaceManager().select()
            iface_name = iface.get("name")
        except Exception as e:
            raise RuntimeError(f"failed to select interface: {e}")

    # Prepare capture queue and capture thread
    pkt_q: Queue = Queue(maxsize=getattr(MAX_QUEUE_SIZE, "value", MAX_QUEUE_SIZE))
    local_stop = stop_event or Event()
    cap = PacketCapture(iface_name)
    t_cap = cap.start_stream(pkt_q, local_stop)

    # flow builder
    fb = FlowBuilder(expiration_window=FLOW_EXPIRATION_SECONDS)

    alerts_path = ALERTS_DIR / ALERTS_FILENAME
    print(f"[rt] capturing on {iface_name}; model={model_path}; alerts -> {alerts_path}")

    # helper to process and emit a flow record
    def _process_flow(rec: dict):
        try:
            feat = features_from_record(rec)
            vec = [float(feat[k]) for k in FEATURE_ORDER]
            import numpy as _np

            X = _np.asarray([vec], dtype=float)
            anom, pred = det.score(X)
            is_anom = int(pred[0]) == -1

            if debug:
                print(
                    f"[flow] src={rec['endpointA_ip']}:{rec['endpointA_port']} "
                    f"dst={rec['endpointB_ip']}:{rec['endpointB_port']} "
                    f"pkts={rec['packet_count']} bytes={rec['byte_count']} score={anom[0]:.6f} pred={int(pred[0])}"
                )

            alert = {
                "time_scored": time(),
                "anomaly_score": float(anom[0]),
                "prediction": int(pred[0]),
                "flow": rec,
                "features": {k: float(feat[k]) for k in FEATURE_ORDER},
            }

            if is_anom:
                _save_jsonl(alert, alerts_path)
                print(
                    f"[ALERT] score={anom[0]:.4f} pred=-1 src={rec['endpointA_ip']}:{rec['endpointA_port']} "
                    f"dst={rec['endpointB_ip']}:{rec['endpointB_port']}"
                )
        except Exception as exc:
            print(f"[err] scoring flow failed: {exc}", file=sys.stderr)

    # Setup signal handlers for graceful shutdown when run from CLI
    def _signal_handler(signum, frame):
        print(f"[rt] received signal {signum}; shutting down...")
        local_stop.set()

    try:
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
    except Exception:
        # some environments (Windows interactive) may restrict signal usage; ignore.
        pass

    last_flush = time()
    try:
        while not local_stop.is_set():
            try:
                pkt = pkt_q.get(timeout=0.5)
                outs = fb.update(pkt)
                if outs:
                    # fb.update may return None or an iterator
                    try:
                        for rec in outs:
                            _process_flow(rec)
                    except TypeError:
                        # single dict
                        if isinstance(outs, dict):
                            _process_flow(outs)
            except Empty:
                # nothing to do
                pass

            # periodic flush of expired flows
            now = time()
            if now - last_flush >= 1.0:
                try:
                    for rec in fb.flush_expired(now):
                        _process_flow(rec)
                except Exception as e:
                    print(f"[err] flush_expired failed: {e}", file=sys.stderr)
                last_flush = now

        # loop exit: perform final draining
        print("[rt] draining and flushing remaining flows...")
    except Exception as e:
        print(f"[err] realtime loop failed: {e}", file=sys.stderr)
    finally:
        # request capture thread stop and join
        local_stop.set()
        try:
            t_cap.join(timeout=2.0)
        except Exception:
            pass

        # flush all remaining flows
        try:
            for rec in fb.flush_all():
                _process_flow(rec)
        except Exception as e:
            print(f"[err] final flush failed: {e}", file=sys.stderr)

        print("[rt] shutdown complete.")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Real-time capture + flow + features + IF detection")
    ap.add_argument("--iface", help="Interface name (prompts if omitted)")
    ap.add_argument("--model", help="Path to .joblib model (prompts if omitted)")
    ap.add_argument("--debug", action="store_true", help="Print every scored flow (for testing)")
    args = ap.parse_args()

    mp = Path(args.model) if args.model else None
    try:
        run_realtime(model_path=mp, iface_name=args.iface, debug=bool(args.debug))
    except Exception as e:
        print(f"[err] {e}")
        sys.exit(1)
