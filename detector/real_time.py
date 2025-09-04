# detector/realtime.py
from __future__ import annotations
from queue import Queue, Empty
from threading import Event
from time import time, sleep
from pathlib import Path
import json

from config import (MAX_QUEUE_SIZE, ALERTS_DIR, MODELS_DIR,
                    ALERTS_FILENAME, MODEL_FILENAME, FLOW_EXPIRATION_SECONDS)
from sniffer.if_manager import InterfaceManager
from sniffer.capture import PacketCapture
from sniffer.parser import FlowBuilder
from detector.metrics import features_from_record, FEATURE_ORDER
from detector.detector import IsolationForestDetector  # class
from utils.chooser import select_file

def _save_jsonl(obj: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")

def run_realtime(model_path: Path | None = None, iface_name: str | None = None) -> None:
    # 1) choose interface (if not provided)
    if iface_name is None:
        iface = InterfaceManager().select()
        iface_name = iface["name"]

    # 2) load model
    model_path = model_path or (MODELS_DIR / MODEL_FILENAME)
    det = IsolationForestDetector()
    det.load(model_path)

    # 3) start capture thread
    packet_q: Queue = Queue(maxsize=MAX_QUEUE_SIZE)
    stop_event = Event()
    cap = PacketCapture(iface_name)
    t_cap = cap.start_stream(packet_q, stop_event)

    # 4) streaming parse + detect
    flow_builder = FlowBuilder(expiration_window=FLOW_EXPIRATION_SECONDS)
    alerts_path = ALERTS_DIR / ALERTS_FILENAME
    print(f"[rt] capturing on {iface_name}; model={model_path}; alerts -> {alerts_path}")

    try:
        last_flush = time()
        while True:
            try:
                pkt = packet_q.get(timeout=0.5)
                # update flows; possibly yields expired flows immediately (gap-based)
                for rec in flow_builder.update(pkt) or []:
                    _score_and_emit(rec, det, alerts_path)
            except Empty:
                pass

            # periodic idle flush (ensure long-idle flows are emitted)
            now = time()
            if now - last_flush >= 1.0:
                for rec in flow_builder.flush_expired(now):
                    _score_and_emit(rec, det, alerts_path)
                last_flush = now

    except KeyboardInterrupt:
        print("\n[rt] stopping...")
    finally:
        # stop capture thread
        stop_event.set()
        t_cap.join(timeout=2.0)
        # flush remaining flows
        for rec in flow_builder.flush_all():
            _score_and_emit(rec, det, alerts_path)
        print("[rt] shutdown complete.")

def _score_and_emit(flow_record: dict, det: IsolationForestDetector, out_path: Path) -> None:
    # compute features
    feat = features_from_record(flow_record)
    # to ndarray in FEATURE_ORDER
    vec = [float(feat[name]) for name in FEATURE_ORDER]
    import numpy as np
    X = np.asarray([vec], dtype=float)
    anom, pred = det.score(X)
    is_anom = int(pred[0]) == -1

    alert = {
        "time_scored": time(),
        "anomaly_score": float(anom[0]),
        "prediction": int(pred[0]),  # -1 anomaly, 1 normal
        "flow": flow_record,
        "features": {k: float(feat[k]) for k in FEATURE_ORDER},
    }
    if is_anom:
        _save_jsonl(alert, out_path)
        print(f"[ALERT] score={anom[0]:.4f} pred=-1 src={flow_record['endpointA_ip']} dst={flow_record['endpointB_ip']}:{flow_record['endpointB_port']}")

if __name__ == "__main__":
    import argparse
    from config import MODEL_FILENAME

    ap = argparse.ArgumentParser(description="Real-time capture + flow + features + IF detection")
    ap.add_argument("--iface", help="Interface name (prompts if omitted)")
    ap.add_argument("--model", default=str((MODELS_DIR / MODEL_FILENAME)), help="Path to .joblib model")
    args = ap.parse_args()

    mp = Path(args.model) if args.model else select_file(MODELS_DIR, ["*.joblib"], title="Select model (.joblib)")
    run_realtime(model_path=mp, iface_name=args.iface)