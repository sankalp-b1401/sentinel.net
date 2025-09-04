# sniffer/capture.py
from __future__ import annotations
from scapy.all import sniff, wrpcap, Packet
from queue import Queue
from threading import Thread, Event
from time import strftime
from pathlib import Path
from typing import Optional, Callable
from config import CAPTURE_DIR, BPF_FILTER

class PacketCapture:

    def _render_progress(current: int, total: int, width: int = 40) -> None:
        """
        Draw a simple in-terminal progress bar like: [██████------] 60% (600/1000)
        """
        if total <= 0:
            return
        ratio = min(max(current / float(total), 0.0), 1.0)
        filled = int(width * ratio)
        bar = "█" * filled + "-" * (width - filled)
        print(f"\r[{bar}] {int(ratio * 100):3d}% ({current}/{total})", end="", flush=True)

    def __init__(self, iface_name: str, bpf: str = BPF_FILTER) -> None:
        self.iface = iface_name
        self.bpf = bpf

    def capture_to_file(self, count: int = 100000, prefix: str = "capture") -> Path:
        """
        Capture up to `count` packets to a PCAP while showing a CLI progress bar.
        """
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        fname = CAPTURE_DIR / f"{prefix}_{strftime('%Y%m%d_%H%M%S')}.pcap"

        packets = []  # we'll store manually so we can show live progress

        def _on_pkt(pkt):
            # append & update progress
            packets.append(pkt)
            if count and len(packets) <= count:
                PacketCapture._render_progress(len(packets), count)

        try:
            # sniff until we reach 'count' (or Ctrl+C)
            sniff(
                iface=self.iface,
                filter=self.bpf,
                store=False,           # we store ourselves in 'packets'
                prn=_on_pkt,
                stop_filter=lambda p: (count > 0 and len(packets) >= count)
            )
        except KeyboardInterrupt:
            # user stopped early
            pass
        except Exception as e:
            print(f"\n[err] capture error on {self.iface}: {e}")

        # finalize bar line
        if count:
            PacketCapture._render_progress(len(packets), count)
        print()  # newline after the bar

        # write the PCAP (only if we actually have packets)
        if packets:
            try:
                wrpcap(str(fname), packets)
                print(f"[ok] saved {len(packets)} packets -> {fname}")
            except Exception as e:
                print(f"[err] failed to write pcap: {e}")
        else:
            print("[warn] no packets captured; nothing written")

        return fname


    def start_stream(self, packet_queue: Queue, stop_event: Event, store: bool = False) -> Thread:
        """
        Start a background thread that streams packets into packet_queue.
        Use stop_event.set() to stop. Returns the Thread object.
        """
        def _prn(pkt: Packet) -> None:
            try:
                packet_queue.put(pkt, block=False)
            except Exception:
                # queue full; drop packet to avoid backpressure lockup
                pass

        def _worker():
            try:
                sniff(
                    iface=self.iface,
                    filter=self.bpf,
                    store=0 if not store else 1,  # default: don't store in memory
                    prn=_prn,
                    stop_filter=lambda p: stop_event.is_set()
                )
            except Exception as e:
                print(f"[err] capture error on {self.iface}: {e}")

        t = Thread(target=_worker, name="PacketCapture", daemon=True)
        t.start()
        return t

if __name__ == "__main__":
    import argparse
    from .if_manager import InterfaceManager  # package-relative
    from config import BPF_FILTER

    parser = argparse.ArgumentParser(description="Packet capture helper")
    parser.add_argument("--iface", help="Interface name to capture on (prompts if omitted)")
    parser.add_argument("--count", type=int, default=2000, help="Number of packets to capture")
    parser.add_argument("--prefix", default="capture", help="Output pcap filename prefix")
    parser.add_argument("--filter", default=BPF_FILTER, help="BPF filter")
    args = parser.parse_args()

    # choose interface if not provided
    iface_name = args.iface
    if not iface_name:
        iface = InterfaceManager().select()
        iface_name = iface["name"]

    print(f"[info] capturing on '{iface_name}' with filter '{args.filter}'")
    try:
        cap = PacketCapture(iface_name, bpf=args.filter)
        cap.capture_to_file(count=args.count, prefix=args.prefix)
    except KeyboardInterrupt:
        print("\n[info] capture interrupted.")
    except Exception as e:
        print(f"[err] capture failed: {e}")
