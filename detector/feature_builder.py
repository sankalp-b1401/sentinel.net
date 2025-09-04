# detector/feature_builder.py
from __future__ import annotations
import json
from pathlib import Path
from typing import Iterator
from detector.metrics import features_from_record
from config import FEATURES_DIR
from utils.progress import render_progress, render_counter, end_line

REQUIRED_KEYS = [
    "protocol","endpointA_ip","endpointA_port",
    "endpointB_ip","endpointB_port",
    "start_time","end_time","packet_count","byte_count",
    "pkts_a_to_b","pkts_b_to_a","bytes_a_to_b","bytes_b_to_a",
]

def iter_flows_from_file(path: str | Path) -> Iterator[dict]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        head = f.read(1)
        if not head:
            return
        f.seek(0)
        if head == "[":
            data = json.load(f)
            for d in data:
                if isinstance(d, dict):
                    yield d
        else:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)

def build_features(in_file: str | Path, out_file: str | Path | None = None) -> Path:
    in_file = Path(in_file)
    out_file = Path(out_file) if out_file else FEATURES_DIR / f"{in_file.stem}_features.json"
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)

    # Peek to decide array vs JSONL and (for arrays) get total for progress bar
    with in_file.open("r", encoding="utf-8") as fh:
        head = fh.read(1)
    is_array = head == "["

    feats, bad = [], 0
    processed = 0

    if is_array:
        # Load once (you likely already do this with arrays)
        import json
        data = json.loads(in_file.read_text(encoding="utf-8"))
        total = len(data)
        for i, flow in enumerate(data, start=1):
            if any(k not in flow for k in REQUIRED_KEYS):
                bad += 1
                render_progress(i, total, prefix="features (skipping invalid)")
                continue
            try:
                feat = features_from_record(flow)
                feat["_endpointA_ip"] = flow.get("endpointA_ip")
                feat["_endpointB_ip"] = flow.get("endpointB_ip")
                feat["_endpointB_port"] = float(flow.get("endpointB_port", 0))
                feat["_start_time"] = float(flow.get("start_time", 0))
                feat["_end_time"] = float(flow.get("end_time", 0))
                feats.append(feat)
            except Exception:
                bad += 1
            render_progress(i, total, prefix="features")
        end_line()
    else:
        # Stream JSONL: unknown total → counter
        import json
        with in_file.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                processed += 1
                flow = json.loads(line)
                if any(k not in flow for k in REQUIRED_KEYS):
                    bad += 1
                    render_counter(processed, prefix="features (skipping invalid)")
                    continue
                try:
                    feat = features_from_record(flow)
                    feat["_endpointA_ip"] = flow.get("endpointA_ip")
                    feat["_endpointB_ip"] = flow.get("endpointB_ip")
                    feat["_endpointB_port"] = float(flow.get("endpointB_port", 0))
                    feat["_start_time"] = float(flow.get("start_time", 0))
                    feat["_end_time"] = float(flow.get("end_time", 0))
                    feats.append(feat)
                except Exception:
                    bad += 1
                render_counter(processed, prefix="features")
        end_line()

    with Path(out_file).open("w", encoding="utf-8") as f:
        json.dump(feats, f, indent=2)
    print(f"[ok] wrote {len(feats)} rows (+{bad} skipped) -> {out_file}")
    return Path(out_file)

# detector/feature_builder.py (bottom)

if __name__ == "__main__":
    import sys
    from config import FLOW_RECORD_DIR
    from utils.chooser import select_file

    src = sys.argv[1] if len(sys.argv) > 1 else None
    if not src:
        # 👇 include *.jsonl as well
        src = select_file(FLOW_RECORD_DIR, ["*.json", "*.jsonl"], title="Select a flow-record file to featurize")
    dst = sys.argv[2] if len(sys.argv) > 2 else None
    build_features(src, dst)

