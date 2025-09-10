from __future__ import annotations
from scapy.all import IP, TCP, UDP, Packet
from time import time
from typing import Iterator, Tuple, Dict, Any
from config import FLOW_EXPIRATION_SECONDS
from scapy.utils import PcapReader
from pathlib import Path
import shutil
import sys

# Map protocol numbers to names for readability in flow records
PROTO_NAME = {6: "TCP", 17: "UDP", 1: "ICMP"}

# Type aliases to clarify intent:
# Endpoint is (ip, port)
Endpoint = Tuple[str, int]
# FlowKey is a tuple (proto, endpointA, endpointB) where endpoints are ordered canonically
FlowKey = Tuple[int, Endpoint, Endpoint]  # (proto, A, B)


def _endpoint_tuple(ip: str, port: int | None) -> Endpoint:
    """Normalize an endpoint where port may be None; ensure port is int."""
    return (ip, int(port) if port is not None else 0)


def _packet_endpoints(pkt: Packet) -> Tuple[Endpoint, Endpoint, int]:
    """
    Extract endpoints and protocol from a scapy Packet.

    - Assumes packet has an IP layer (caller should check).
    - For TCP/UDP extracts ports; otherwise port 0 is used.
    - Returns (src_endpoint, dst_endpoint, proto_number).
    """
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
    """
    Produce a canonical flow key so that A<->B flows are treated the same regardless of direction.
    This uses tuple comparison to determine ordering (ip, port) pairs.
    """
    a = _endpoint_tuple(*ep1)
    b = _endpoint_tuple(*ep2)
    return (proto, a, b) if a <= b else (proto, b, a)


class FlowBuilder:
    """
    Incremental flow builder with expiration.

    - Feed packets with .update(pkt).
    - Call .flush_expired(now) periodically to yield expired flow-record dicts.
    - Call .flush_all() to get all remaining flow records.
    """

    def __init__(self, expiration_window: int = FLOW_EXPIRATION_SECONDS) -> None:
        self.expiration = expiration_window
        # flow_table maps FlowKey -> instance dict holding counters & timestamps
        self.flow_table: Dict[FlowKey, Dict[str, Any]] = {}
        self.id_counter = 0

    def _new_instance(self, pkt: Packet, epA: Endpoint, epB: Endpoint) -> Dict[str, Any]:
        """
        Start a new flow instance based on the first packet seen.
        We store timing, packet/byte counts, per-direction counters, and TCP flag counters.
        """
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

        # Determine which direction the first packet belongs to (A->B or B->A)
        (src_ip, src_port), (_, _), _ = _packet_endpoints(pkt)
        if (src_ip, src_port) == epA:
            inst["pkts_a_to_b"] = 1
            inst["bytes_a_to_b"] = length
        else:
            inst["pkts_b_to_a"] = 1
            inst["bytes_b_to_a"] = length

        # If TCP, inspect flags and increment counters accordingly
        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            if flags & 0x02: inst["syn_count"] = 1
            if flags & 0x10: inst["ack_count"] = 1
            if flags & 0x01: inst["fin_count"] = 1
            if flags & 0x04: inst["rst_count"] = 1
        return inst

    def _update_instance(self, inst: Dict[str, Any], pkt: Packet, epA: Endpoint, epB: Endpoint) -> None:
        """
        Update an existing flow instance with another packet.
        - Updates packet_count, byte_count, end_time.
        - Updates directional counters based on packet source.
        - Updates TCP flags if present.
        """
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
        """
        Convert internal instance dict into a stable flow record dict suitable for JSON export.
        Includes protocol name, endpoints, counts and derived average packet size.
        """
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
        """
        Feed a packet into the builder.

        - If packet is not IP it is ignored.
        - If it starts a new flow, create a new instance.
        - If it continues an existing flow but the last packet time exceeded expiration,
          yield the old flow record and start a new instance.
        - Otherwise, update counters in-place.

        The function may return None, a single dict, or an iterator of dicts (older implementations varied).
        The caller handles these cases.
        """
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
        # If flow idle time exceeded expiration, yield old flow and start new
        if now - last["end_time"] > self.expiration:
            yield self._make_record(key, last)
            self.flow_table[key] = self._new_instance(pkt, epA, epB)
        else:
            self._update_instance(last, pkt, epA, epB)

    def flush_expired(self, now_ts: float | None = None) -> Iterator[Dict[str, Any]]:
        """
        Iterate and yield flow records that have expired relative to now_ts.
        This is useful for periodic flushing in streaming scenarios.
        """
        now_ts = time() if now_ts is None else now_ts
        to_evict = []
        for key, inst in self.flow_table.items():
            if now_ts - inst["end_time"] > self.expiration:
                yield self._make_record(key, inst)
                to_evict.append(key)
        for k in to_evict:
            self.flow_table.pop(k, None)

    def flush_all(self) -> Iterator[Dict[str, Any]]:
        """Yield all remaining flow records and clear the internal table."""
        for key, inst in list(self.flow_table.items()):
            yield self._make_record(key, inst)
            self.flow_table.pop(key, None)


def parse_pcap_to_flow_generator(pcap_path: Path | str, expiration_window: int | None = None) -> Iterator[dict]:
    """
    Generator over flow dicts produced from a pcap file.

    - Reads pcap sequentially using scapy.utils.PcapReader.
    - Converts packets into flows using FlowBuilder with given expiration.
    - Yields flow dicts as they are produced.
    """
    p = Path(pcap_path)
    if expiration_window is None:
        expiration_window = FLOW_EXPIRATION_SECONDS
    fb = FlowBuilder(expiration_window)
    with PcapReader(str(p)) as pr:
        for pkt in pr:
            outs = fb.update(pkt)
            if outs:
                # fb.update returns None or an iterator/list; handle both
                try:
                    for rec in outs:
                        yield rec
                except TypeError:
                    if isinstance(outs, dict):
                        yield outs
        # finally flush all remaining instances
        for rec in fb.flush_all():
            yield rec

# bottom of sniffer/parser.py (replace existing __main__ block)
if __name__ == "__main__":
    # CLI usage: parse a pcap, optionally send to detector or write JSONL to disk.
    import argparse, json
    from pathlib import Path
    from config import FLOW_RECORD_DIR, CAPTURE_DIR, AUTH_TRANSPORT
    from utils.chooser import select_file

    parser = argparse.ArgumentParser(description="Parse PCAP into flow records (streaming, 30s expiry).")
    parser.add_argument("pcap", nargs="?", help="Path to .pcap/.pcapng (menu if omitted)")
    parser.add_argument("--out", help="Output file; default: flow_records/<pcap>_flow.jsonl (streaming JSONL)")
    parser.add_argument("--expire", type=int, default=30, help="Flow idle expiry seconds (default 30)")
    parser.add_argument("--send", action="store_true", help="Send flows to detector immediately (requires configured HTTP transport)")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size to send (when --send).")
    args = parser.parse_args()

    try:
        pcap_path = Path(args.pcap) if args.pcap else select_file(
            CAPTURE_DIR, ["*.pcap", "*.pcapng"], title="Select a PCAP to parse"
        )
        FLOW_RECORD_DIR.mkdir(parents=True, exist_ok=True)

        fb = FlowBuilder(expiration_window=args.expire)
        out_path = Path(args.out) if args.out else FLOW_RECORD_DIR / f"{pcap_path.stem}_flow.jsonl"

        send_mode = bool(args.send)
        batch_size = max(1, int(args.batch_size))

        if send_mode and AUTH_TRANSPORT != "http":
            # If HTTP transport not configured, fall back to saving locally to avoid data loss
            print("[warn] HTTP transport not enabled in config; falling back to saving locally.")
            send_mode = False

        sender = None
        if send_mode:
            from sniffer.batch_sender import BatchSender
            sender = BatchSender()
            print("[info] SEND mode: flows will be posted to detector in batches.")
            print("[info] If a send fails, the affected flows will be written to disk (no data lost).")
        else:
            print(f"[info] SAVE mode: flow records will be written to {out_path}")

        # simple progress printer used only in SAVE mode to give visual feedback
        def _print_progress(packets: int, flows: int, last_len: int | None = None) -> None:
            try:
                cols = shutil.get_terminal_size((80, 20)).columns
            except Exception:
                cols = 80
            base = f"Packets={packets}, Flows={flows}"
            max_bar = max(10, cols - len(base) - 20)
            bar_filled = min(max_bar, packets % (max_bar + 1))
            bar = "#" * bar_filled + "-" * (max_bar - bar_filled)
            line = f"[parsing] {base} |{bar}|"
            if len(line) < cols:
                line = line + " " * (cols - len(line))
            else:
                line = line[:cols]
            sys.stdout.write("\r" + line)
            sys.stdout.flush()

        sender = None

        # iterate packets and produce flows
        count_pkts = 0
        count_flows = 0
        batch = []

        with PcapReader(str(pcap_path)) as pr, out_path.open("a", encoding="utf-8") as fh:
            for pkt in pr:
                count_pkts += 1
                outs = fb.update(pkt)
                if outs:
                    for rec in outs:
                        count_flows += 1
                        if send_mode and sender:
                            batch.append(rec)
                            if len(batch) >= batch_size:
                                ok, resp, failed = sender.send_batch(batch)
                                if not ok:
                                    for br in failed:
                                        fh.write(json.dumps(br) + "\n")
                                    fh.flush()
                                batch = []
                        else:
                            fh.write(json.dumps(rec) + "\n")

                # update progress display every 100 packets (only in SAVE mode)
                if not send_mode and (count_pkts % 100 == 0):
                    _print_progress(count_pkts, count_flows)

            # flush remaining flows from builder
            for rec in fb.flush_all():
                count_flows += 1
                if send_mode and sender:
                    batch.append(rec)
                else:
                    fh.write(json.dumps(rec) + "\n")

            # final flush of any leftover batch
            if send_mode and sender and batch:
                ok, resp, failed = sender.send_batch(batch)
                if not ok and failed:
                    for br in failed:
                        fh.write(json.dumps(br) + "\n")
                batch = []

        # ensure final progress printed and newline
        if not send_mode:
            _print_progress(count_pkts, count_flows)
            sys.stdout.write("\n")

        if sender:
            try:
                sender.close()
            except Exception:
                pass

        print(f"[ok] parsed packets={count_pkts}, flows={count_flows} -> output={out_path if not send_mode else 'sent to detector (verify server logs)'}")
    except Exception as e:
        print(f"[err] {e}")
