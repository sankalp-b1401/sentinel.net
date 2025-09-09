# detector/queue_worker.py
import json
from pathlib import Path
from threading import Thread
from queue import Queue
from time import time
from typing import List, Dict, Any
import logging

from detector.metrics import features_from_record, FEATURE_ORDER
from detector.detector import IsolationForestDetector
from config import MODELS_DIR, ALERTS_DIR, INBOX_DIR, STATUS_DIR

log = logging.getLogger("detector.queue_worker")
log.setLevel(logging.INFO)

# ensure dirs exist
ALERTS_DIR.mkdir(parents=True, exist_ok=True)
INBOX_DIR.mkdir(parents=True, exist_ok=True)
STATUS_DIR.mkdir(parents=True, exist_ok=True)


def _score_batch(det, rows):
    import numpy as np
    from time import time
    feats = []
    Xlist = []
    for r in rows:
        try:
            f = features_from_record(r)
            feats.append(f)
            Xlist.append([float(f[k]) for k in FEATURE_ORDER])
        except Exception:
            # keep placeholder row so indexing remains consistent
            feats.append({k: 0.0 for k in FEATURE_ORDER})
            Xlist.append([0.0] * len(FEATURE_ORDER))
    X = np.asarray(Xlist, dtype=float)
    if X.size == 0:
        return []

    anom_scores, preds = det.score(X)

    # Preferred selection: use model predictions (pred == -1). If no -1 present, fallback to threshold if available.
    alert_indices = [i for i, p in enumerate(preds) if int(p) == -1]
    if len(alert_indices) == 0 and getattr(det, "threshold", None) is not None:
        thr = float(det.threshold)
        alert_indices = [i for i in range(len(rows)) if float(anom_scores[i]) >= thr]

    alerts = []
    for i in alert_indices:
        alert = {
            "time_scored": time(),
            "anomaly_score": float(anom_scores[i]),
            "prediction": int(preds[i]),
            "flow": rows[i],
            "features": {k: float(feats[i][k]) for k in FEATURE_ORDER},
        }
        alerts.append(alert)
    return alerts

def _process_job(job: Dict[str, Any], model_path: str):
    """
    Job structure: {"batch_id": str, "path": "/absolute/path/to/jsonl", "meta": {...}, "claims": {...}}
    """
    det = IsolationForestDetector()
    det.load(model_path)

    batch_id = job.get("batch_id", "unknown")
    path = Path(job.get("path"))
    base = path.stem  # like 'batch_20250904_..._<uuid>'
    # Build unique alerts path (avoid overwriting)
    alerts_out_base = ALERTS_DIR / f"{base}_alerts"
    alerts_out = alerts_out_base.with_suffix(".jsonl")
    # If file exists, append _vN
    v = 0
    while alerts_out.exists():
        v += 1
        alerts_out = alerts_out_base.with_name(f"{alerts_out_base.name}_v{v}").with_suffix(".jsonl")

    status_file = STATUS_DIR / f"{base}.json"

    rows = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    # skip meta header line if present
                    obj = json.loads(line)
                    if isinstance(obj, dict) and "_meta" in obj:
                        continue
                    rows.append(obj)
                except Exception:
                    continue
    except Exception as e:
        log.exception("failed to read batch file %s: %s", path, e)
        status_file.write_text(json.dumps({"batch_id": batch_id, "status": "read_failed", "error": str(e)}), encoding="utf-8")
        return

    try:
        alerts = _score_batch(det, rows)
    except Exception as e:
        log.exception("scoring failure for %s: %s", path, e)
        status_file.write_text(json.dumps({"batch_id": batch_id, "status": "scoring_failed", "error": str(e)}), encoding="utf-8")
        return

    # persist alerts (create a new file per batch, avoid overwrite)
    try:
        if alerts:
            with alerts_out.open("w", encoding="utf-8") as fh:
                for a in alerts:
                    fh.write(json.dumps(a) + "\n")
        # Optionally create a visualization PNG of the scored batch
        try:
            # build feature matrix and anomaly scores for visualization
            import numpy as _np
            feats = []
            for r in rows:
                try:
                    f = features_from_record(r)
                    feats.append([float(f[k]) for k in FEATURE_ORDER])
                except Exception:
                    feats.append([0.0] * len(FEATURE_ORDER))
            Xmat = _np.asarray(feats, dtype=float)
            # compute anomaly scores using detector (same as used earlier)
            anom_scores, preds = det.score(Xmat)
            alert_indices = [i for i in range(len(rows)) if int(preds[i]) == -1]
            # prefer model threshold if available (use same selection as _score_batch)
            if getattr(det, "threshold", None) is not None:
                thr = float(det.threshold)
                alert_indices = [i for i in range(len(rows)) if float(anom_scores[i]) >= thr]
            # call visualize helper
            from detector.visualize import plot_alerts_scatter
            png_path = str(alerts_out.with_suffix(".png"))
            plot_alerts_scatter(Xmat, anom_scores, alert_indices, out_path=png_path,
                                title=f"Batch {base} - alerts={len(alert_indices)}")
        except Exception as e:
            # visualization should not break processing
            log.debug("visualization skipped/failed for %s: %s", base, e)

        # write status metadata (safe summary)
        status = {
            "batch_id": batch_id,
            "batch_path": str(path),
            "alerts_count": len(alerts),
            "alerts_path": str(alerts_out) if alerts else None,
            "status": "scored",
            "rows_scored": len(rows),
            "ts_scored": time(),
        }
        status_file.write_text(json.dumps(status), encoding="utf-8")
        log.info("scored batch=%s rows=%d alerts=%d -> %s", batch_id, len(rows), len(alerts), alerts_out)
    except Exception as e:
        log.exception("failed to persist alerts/status for batch %s: %s", batch_id, e)
        status_file.write_text(json.dumps({"batch_id": batch_id, "status": "persist_failed", "error": str(e)}), encoding="utf-8")

def _worker_loop(q: Queue, model_path: str):
    log.info("queue worker starting with model %s", model_path)
    while True:
        job = q.get()
        if job is None:
            log.info("worker received shutdown sentinel, exiting.")
            break
        try:
            _process_job(job, model_path)
        except Exception as e:
            log.exception("unexpected worker error: %s", e)


def start_worker(q: Queue, model_path: str):
    t = Thread(target=_worker_loop, args=(q, model_path), daemon=True)
    t.start()
    return t
