# detector/detector.py
from __future__ import annotations
import json
from pathlib import Path
import argparse
import numpy as np
from joblib import dump, load
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from detector.metrics import FEATURE_ORDER
from config import FEATURES_DIR, MODELS_DIR
from utils.chooser import select_file
from utils.progress import render_progress, end_line, render_counter
import datetime

SCALER_SUFFIX = ".scaler.joblib"

class IsolationForestDetector:
    def __init__(self, contamination: float = 0.01, n_estimators: int = 300, seed: int = 42):
        self.model: IsolationForest | None = None
        self.scaler: RobustScaler | None = None
        self.params = dict(n_estimators=n_estimators, contamination=contamination,
                           random_state=seed, n_jobs=-1, max_samples="auto")
        self.threshold = None
        self.threshold_percentile = None

    def fit(self, X: np.ndarray) -> None:
        """Fit model on already-scaled X (caller should scale with RobustScaler)."""
        self.model = IsolationForest(**self.params)
        self.model.fit(X)

    def save(self, path: str | Path, overwrite: bool = False, timestamp_version: bool = True) -> None:
        """
        Save model and scaler sidecar.
        - If overwrite==False and path exists, create a versioned filename using timestamp.
        - If timestamp_version==True we append _YYYYmmdd_HHMMSS before extension.
        """
        if self.model is None:
            raise RuntimeError("Model not trained; nothing to save.")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        # If file exists and overwrite False, create versioned path
        if p.exists() and not overwrite:
            import datetime
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            new_name = f"{p.stem}_{ts}{p.suffix}"
            p = p.parent / new_name

        dump(self.model, str(p))

        # Save scaler sidecar (if present).
        if self.scaler is not None:
            scaler_path = p.parent / (p.name + SCALER_SUFFIX)
            dump(self.scaler, str(scaler_path))

        # Save metadata sidecar (model params + optional threshold)
        meta = {
            "saved_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "params": self.params,
        }
        # include threshold if detector has one
        if hasattr(self, "threshold") and self.threshold is not None:
            meta["threshold_percentile"] = float(getattr(self, "threshold_percentile", -1))
            meta["threshold_value"] = float(self.threshold)
        # path to scaler sidecar
        if self.scaler is not None:
            meta["scaler_sidecar"] = str(scaler_path.name)
        meta_path = p.parent / (p.name + ".meta.json")
        with open(meta_path, "w", encoding="utf-8") as mh:
            json.dump(meta, mh, indent=2)

    def load(self, path: str | Path) -> None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"model not found: {p}")
        obj = load(str(p))
        if not isinstance(obj, IsolationForest):
            raise TypeError(
                f"Loaded object from {p} is type {type(obj)}, "
                "but expected sklearn.ensemble.IsolationForest"
            )
        self.model = obj

        # Load scaler sidecar if present
        scaler_path = p.parent / (p.name + SCALER_SUFFIX)
        if scaler_path.exists():
            self.scaler = load(str(scaler_path))
        else:
            self.scaler = None

        # Try to load metadata sidecar (.meta.json)
        meta_path = p.parent / (p.name + ".meta.json")
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as mh:
                    meta = json.load(mh)
                if "threshold_value" in meta:
                    self.threshold = float(meta["threshold_value"])
                    self.threshold_percentile = float(meta.get("threshold_percentile", -1))
                else:
                    self.threshold = None
                    self.threshold_percentile = None
            except Exception as e:
                print(f"[warn] failed to load model metadata: {e}")
                self.threshold = None
                self.threshold_percentile = None
        else:
            self.threshold = None
            self.threshold_percentile = None


    def score(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Score raw X. If scaler exists, apply it first."""
        if self.model is None:
            raise RuntimeError("Model not loaded")

        X_proc = X
        if self.scaler is not None:
            X_proc = self.scaler.transform(X)

        # ensure the model returns numpy arrays consistently
        anom = -np.asarray(self.model.score_samples(X_proc), dtype=float)
        pred = np.asarray(self.model.predict(X_proc), dtype=int)  # -1 anomaly, 1 normal

        # defensive: if shapes mismatch or X_proc is empty, return zero-length arrays
        if anom.ndim == 0:
            anom = np.atleast_1d(anom)
        if pred.ndim == 0:
            pred = np.atleast_1d(pred)

        return anom, pred

def _read_features_json(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of feature dicts")
    return data

def _rows_to_matrix(rows: list[dict]) -> tuple[np.ndarray, list[int]]:
    n = len(rows)
    X, keep = [], []
    for i, r in enumerate(rows, start=1):
        try:
            vec = [float(r[name]) for name in FEATURE_ORDER]
            if any(np.isnan(v) or np.isinf(v) for v in vec):
                pass
            else:
                X.append(vec); keep.append(i-1)
        except Exception:
            pass
        render_progress(i, n, prefix="vectorizing")
    end_line()
    return np.asarray(X, dtype=float), keep

def _save_json(obj, out_path: str) -> None:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def main():
    p = argparse.ArgumentParser(description="Isolation Forest detector (train/score).")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_tr = sub.add_parser("train")
    p_tr.add_argument("train_features", nargs="?", help="Features JSON (if omitted, interactive menu)")
    p_tr.add_argument("model_path", nargs="?", help="Where to save model (default: detector/models/iforest_v1.joblib)")
    p_tr.add_argument("--contamination", type=float, default=0.01)
    p_tr.add_argument("--n_estimators", type=int, default=300)
    p_tr.add_argument("--seed", type=int, default=42)

    p_sc = sub.add_parser("score")
    p_sc.add_argument("model_path", nargs="?", help="Path to saved model (.joblib) (if omitted, interactive menu)")
    p_sc.add_argument("score_features", nargs="?", help="Features JSON to score (if omitted, interactive menu)")
    p_sc.add_argument("alerts_out", nargs="?", help="Where to write alerts JSON (default: detector/alerts/alerts.json)")
    grp = p_sc.add_mutually_exclusive_group()
    grp.add_argument("--top-k", type=int, default=100)
    grp.add_argument("--percentile", type=float)

    args = p.parse_args()

    if args.cmd == "train":
        # interactive features path
        train_path = args.train_features or select_file(FEATURES_DIR, ["*.json", "*.jsonl"], title="Select TRAIN features JSON")
        model_path = Path(args.model_path or (MODELS_DIR / "iforest_v1.joblib"))

        rows = _read_features_json(str(train_path))
        X, _ = _rows_to_matrix(rows)
        if X.size == 0:
            raise SystemExit("No usable training rows.")

        # Fit a robust scaler to protect against remaining outliers
        print(f"[info] fitting RobustScaler on {X.shape[0]} rows ...")
        scaler = RobustScaler(with_centering=True, with_scaling=True, quantile_range=(25.0, 75.0))
        Xs = scaler.fit_transform(X)

        det = IsolationForestDetector(args.contamination, args.n_estimators, args.seed)
        det.scaler = scaler
        print(f"[info] training IF on {Xs.shape[0]} rows ...")
        det.fit(Xs)

        # compute anomaly scores on the (scaled) training set for diagnostic info
        print("[info] computing anomaly scores on training set for diagnostics ...")
        anom_train = -det.model.score_samples(Xs)  # higher = more anomalous
        import numpy as _np
        p50 = float(_np.percentile(anom_train, 50))
        p90 = float(_np.percentile(anom_train, 90))
        p95 = float(_np.percentile(anom_train, 95))
        p99 = float(_np.percentile(anom_train, 99))
        mean = float(_np.mean(anom_train))
        std = float(_np.std(anom_train))
        print(f"[diagnostic] train rows={Xs.shape[0]} mean={mean:.6f} std={std:.6f} p50={p50:.6f} p90={p90:.6f} p95={p95:.6f} p99={p99:.6f}")

        # Decide threshold percentile to persist: default to 99th percentile (configurable manually)
        threshold_percentile = 99.0
        threshold_value = float(_np.percentile(anom_train, threshold_percentile))
        det.threshold = threshold_value
        det.threshold_percentile = float(threshold_percentile)

        det.scaler = scaler
        det.save(str(model_path))
        print(f"[ok] trained -> {model_path} (scaler and meta saved alongside)")
        print(f"[ok] persisted threshold: percentile={threshold_percentile} value={threshold_value:.6f}")

    else:  # score
        model_path = args.model_path or select_file(MODELS_DIR, ["*.joblib"], title="Select model (.joblib)")
        score_path = args.score_features or select_file(FEATURES_DIR, ["*.json", "*.jsonl"], title="Select SCORE features JSON")
        alerts_out = args.alerts_out or (Path("detector/alerts/alerts.json"))
        rows = _read_features_json(str(score_path))
        X, keep = _rows_to_matrix(rows)
        if X.size == 0:
            raise SystemExit("No usable scoring rows.")
        det = IsolationForestDetector()
        det.load(str(model_path))
        print(f"[info] scoring {X.shape[0]} rows ...")
        anom, pred = det.score(X)

                # compute anomaly scores and predictions
        anom, pred = det.score(X)

        # selection policy
        selected_idx = []
        if args.percentile is not None:
            thr = float(np.percentile(anom, args.percentile))
            selected_idx = np.where(anom >= thr)[0]
            order = selected_idx[np.argsort(-anom[selected_idx])]
            print(f"[info] selecting percentile={args.percentile} thr={thr:.6f} => {len(order)} rows")
        elif args.top_k:
            k = min(args.top_k, len(anom))
            order = np.argsort(-anom)[:k]
            print(f"[info] selecting top-k={k}")
        elif getattr(det, "threshold", None) is not None:
            thr = float(det.threshold)
            selected_idx = np.where(anom >= thr)[0]
            order = selected_idx[np.argsort(-anom[selected_idx])]
            print(f"[info] selecting model metadata threshold={det.threshold} (percentile={getattr(det,'threshold_percentile',None)}) -> {len(order)} rows")
        else:
            # fallback to model prediction -1
            order = [i for i in range(len(pred)) if int(pred[i]) == -1]
            order = np.array(order)
            print(f"[info] selecting pred == -1 -> {len(order)} rows")

        alerts = []
        for rank, i in enumerate(order, start=1):
            row = rows[keep[i]]
            feat_vec = {FEATURE_ORDER[j]: float(X[i, j]) for j in range(len(FEATURE_ORDER))}
            alerts.append({
                "rank": rank,
                "anomaly_score": float(anom[i]),
                "prediction": int(pred[i]),
                "trace": {k: row.get(k) for k in ["_endpointA_ip","_endpointB_ip","_endpointB_port","_start_time","_end_time"]},
                "features": feat_vec,
            })
        _save_json(alerts, str(alerts_out))
        print(f"[ok] wrote {len(alerts)} alerts -> {alerts_out}")

if __name__ == "__main__":
    main()
