# detector/detector.py
from __future__ import annotations
import json
from pathlib import Path
import argparse
import numpy as np
from joblib import dump, load
from sklearn.ensemble import IsolationForest
from detector.metrics import FEATURE_ORDER
from config import FEATURES_DIR, MODELS_DIR
from utils.chooser import select_file
from utils.progress import render_progress, end_line, render_counter

class IsolationForestDetector:
    def __init__(self, contamination: float = 0.01, n_estimators: int = 300, seed: int = 42):
        self.model: IsolationForest | None = None
        self.params = dict(n_estimators=n_estimators, contamination=contamination,
                           random_state=seed, n_jobs=-1, max_samples="auto")

    def fit(self, X: np.ndarray) -> None:
        self.model = IsolationForest(**self.params)
        self.model.fit(X)

    def save(self, path: str | Path) -> None:
        if self.model is None: raise RuntimeError("Model not trained")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        dump(self.model, path)

    def load(self, path: str | Path) -> None:
        self.model = load(path)

    def score(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        if self.model is None: raise RuntimeError("Model not loaded")
        anom = -self.model.score_samples(X)
        pred = self.model.predict(X)  # -1 anomaly, 1 normal
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
        train_path = args.train_features or select_file(FEATURES_DIR, ["*.json"], title="Select TRAIN features JSON")
        model_path = args.model_path or (MODELS_DIR / "iforest_v1.joblib")
        rows = _read_features_json(str(train_path))
        X, _ = _rows_to_matrix(rows)
        if X.size == 0: raise SystemExit("No usable training rows.")
        det = IsolationForestDetector(args.contamination, args.n_estimators, args.seed)
        print(f"[info] training IF on {X.shape[0]} rows ...")
        det.fit(X)
        det.save(str(model_path))
        print(f"[ok] trained -> {model_path}")

    else:  # score
        model_path = args.model_path or select_file(MODELS_DIR, ["*.joblib"], title="Select model (.joblib)")
        score_path = args.score_features or select_file(FEATURES_DIR, ["*.json"], title="Select SCORE features JSON")
        alerts_out = args.alerts_out or (Path("detector/alerts/alerts.json"))
        rows = _read_features_json(str(score_path))
        X, keep = _rows_to_matrix(rows)
        if X.size == 0: raise SystemExit("No usable scoring rows.")
        det = IsolationForestDetector()
        det.load(str(model_path))
        print(f"[info] scoring {X.shape[0]} rows ...")
        anom, pred = det.score(X)

        if args.percentile is not None:
            thr = np.percentile(anom, args.percentile)
            idx = np.where(anom >= thr)[0]
            order = idx[np.argsort(-anom[idx])]
        else:
            k = min(args.top_k or 0, len(anom))
            order = np.argsort(-anom)[:k]

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
