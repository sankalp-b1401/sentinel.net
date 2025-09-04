# sniffer/parser.py
from __future__ import annotations
from scapy.all import IP, TCP, UDP, Packet
from time import time
from typing import Iterator, Tuple, Dict, Any
from config import FLOW_EXPIRATION_SECONDS

PROTO_NAME = {6: "TCP", 17: "UDP", 1: "ICMP"}

Endpoint = Tuple[str, int]
FlowKey = Tuple[int, Endpoint, Endpoint]  # (proto, A, B)

def _endpoint_tuple(ip: str, port: int | None) -> Endpoint:
    return (ip, int(port) if port is not None else 0)

def _packet_endpoints(pkt: Packet) -> Tuple[Endpoint, Endpoint, int]:
    ip = pkt[IP]
    proto = int(ip.proto)
    src_ip, dst_ip = ip.src, ip.dst
    if TCP in pkt:
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif UDP in pkt:
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
    else:
        sport, dport = 0, 0
    return (src_ip, sport), (dst_ip, dport), proto

def _canonical_key(ep1: Endpoint, ep2: Endpoint, proto: int) -> FlowKey:
    a = _endpoint_tuple(*ep1)
    b = _endpoint_tuple(*ep2)
    return (proto, a, b) if a <= b else (proto, b, a)

class FlowBuilder:
    """
    Incremental flow builder with expiration. Feed packets with .update(pkt).
    Call .flush_expired(now) periodically to yield expired flow-record dicts.
    """
    def __init__(self, expiration_window: int = FLOW_EXPIRATION_SECONDS) -> None:
        self.expiration = expiration_window
        self.flow_table: Dict[FlowKey, Dict[str, Any]] = {}
        self.id_counter = 0

    def _new_instance(self, pkt: Packet, epA: Endpoint, epB: Endpoint) -> Dict[str, Any]:
        length = int(len(pkt))
        inst = {
            "id": self.id_counter,
            "start_time": float(pkt.time),
            "end_time": float(pkt.time),
            "packet_count": 1,
            "byte_count": length,
            "pkts_a_to_b": 0,
            "pkts_b_to_a": 0,
            "bytes_a_to_b": 0,
            "bytes_b_to_a": 0,
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
        }
        self.id_counter += 1
        (src_ip, src_port), (_, _), _ = _packet_endpoints(pkt)
        if (src_ip, src_port) == epA:
            inst["pkts_a_to_b"] = 1
            inst["bytes_a_to_b"] = length
        else:
            inst["pkts_b_to_a"] = 1
            inst["bytes_b_to_a"] = length

        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            if flags & 0x02: inst["syn_count"] = 1
            if flags & 0x10: inst["ack_count"] = 1
            if flags & 0x01: inst["fin_count"] = 1
            if flags & 0x04: inst["rst_count"] = 1
        return inst

    def _update_instance(self, inst: Dict[str, Any], pkt: Packet, epA: Endpoint, epB: Endpoint) -> None:
        length = int(len(pkt))
        inst["packet_count"] += 1
        inst["byte_count"] += length
        inst["end_time"] = float(pkt.time)

        (src_ip, src_port), (_, _), _ = _packet_endpoints(pkt)
        if (src_ip, src_port) == epA:
            inst["pkts_a_to_b"] += 1
            inst["bytes_a_to_b"] += length
        else:
            inst["pkts_b_to_a"] += 1
            inst["bytes_b_to_a"] += length

        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            if flags & 0x02: inst["syn_count"] += 1
            if flags & 0x10: inst["ack_count"] += 1
            if flags & 0x01: inst["fin_count"] += 1
            if flags & 0x04: inst["rst_count"] += 1

    def _make_record(self, key: FlowKey, inst: Dict[str, Any]) -> Dict[str, Any]:
        proto, epA, epB = key
        a_ip, a_port = epA
        b_ip, b_port = epB
        total_pkts = inst["packet_count"]
        avg_size = inst["byte_count"] / total_pkts if total_pkts else 0.0
        return {
            "id": inst["id"],
            "protocol": PROTO_NAME.get(proto, str(proto)),
            "endpointA_ip": a_ip,
            "endpointA_port": a_port,
            "endpointB_ip": b_ip,
            "endpointB_port": b_port,
            "start_time": inst["start_time"],
            "end_time": inst["end_time"],
            "packet_count": total_pkts,
            "byte_count": inst["byte_count"],
            "avg_size": avg_size,
            "pkts_a_to_b": inst["pkts_a_to_b"],
            "pkts_b_to_a": inst["pkts_b_to_a"],
            "bytes_a_to_b": inst["bytes_a_to_b"],
            "bytes_b_to_a": inst["bytes_b_to_a"],
            "syn_count": inst["syn_count"],
            "ack_count": inst["ack_count"],
            "fin_count": inst["fin_count"],
            "rst_count": inst["rst_count"],
        }

    def update(self, pkt: Packet) -> Iterator[Dict[str, Any]]:
        if IP not in pkt:
            return  # non-IP ignored
        ep_src, ep_dst, proto = _packet_endpoints(pkt)
        key = _canonical_key(ep_src, ep_dst, proto)
        epA, epB = key[1], key[2]
        now = float(pkt.time)

        if key not in self.flow_table:
            self.flow_table[key] = self._new_instance(pkt, epA, epB)
            return

        last = self.flow_table[key]
        if now - last["end_time"] > self.expiration:
            # expire the last instance and start a new one
            yield self._make_record(key, last)
            self.flow_table[key] = self._new_instance(pkt, epA, epB)
        else:
            self._update_instance(last, pkt, epA, epB)

    def flush_expired(self, now_ts: float | None = None) -> Iterator[Dict[str, Any]]:
        now_ts = time() if now_ts is None else now_ts
        to_evict = []
        for key, inst in self.flow_table.items():
            if now_ts - inst["end_time"] > self.expiration:
                yield self._make_record(key, inst)
                to_evict.append(key)
        for k in to_evict:
            self.flow_table.pop(k, None)

    def flush_all(self) -> Iterator[Dict[str, Any]]:
        for key, inst in list(self.flow_table.items()):
            yield self._make_record(key, inst)
            self.flow_table.pop(key, None)

if __name__ == "__main__":
    import argparse, json
    from pathlib import Path
    from scapy.utils import PcapReader
    from config import FLOW_RECORD_DIR, CAPTURE_DIR
    from utils.chooser import select_file
    from utils.progress import render_counter, end_line
    from sniffer.parser import FlowBuilder  # ensure correct import

    parser = argparse.ArgumentParser(description="Parse PCAP into flow records (streaming, 30s expiry).")
    parser.add_argument("pcap", nargs="?", help="Path to .pcap/.pcapng (menu if omitted)")
    parser.add_argument("--out", help="Output file; default: flow_records/<pcap>_flow.jsonl (streaming JSONL)")
    parser.add_argument("--jsonl", action="store_true", help="Force JSONL; otherwise JSONL is default for streaming")
    parser.add_argument("--expire", type=int, default=30, help="Flow idle expiry seconds (default 30)")
    args = parser.parse_args()

    try:
        pcap_path = Path(args.pcap) if args.pcap else select_file(
            CAPTURE_DIR, ["*.pcap", "*.pcapng"], title="Select a PCAP to parse"
        )
        FLOW_RECORD_DIR.mkdir(parents=True, exist_ok=True)

        # Stream packets
        fb = FlowBuilder(expiration_window=args.expire)
        out_path = Path(args.out) if args.out else FLOW_RECORD_DIR / f"{pcap_path.stem}_flow.jsonl"
        count_pkts = 0
        count_flows = 0

        with PcapReader(str(pcap_path)) as pr, out_path.open("w", encoding="utf-8") as fh:
            for pkt in pr:
                count_pkts += 1
                outs = fb.update(pkt)
                if outs:
                    for rec in outs:
                        fh.write(json.dumps(rec) + "\n")
                        count_flows += 1
                if (count_pkts % 1000) == 0:
                    render_counter(count_pkts, prefix=f"flows={count_flows}")
            # periodic flush of any remaining expired flows
            remaining = list(fb.flush_all())
            for rec in remaining:
                fh.write(json.dumps(rec) + "\n")
                count_flows += 1
            end_line()

        print(f"[ok] parsed packets={count_pkts}, flows={count_flows} -> {out_path}")
        print("[hint] feature_builder can read JSONL directly.")
    except Exception as e:
        print(f"[err] {e}")
