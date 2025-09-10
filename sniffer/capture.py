# sniffer/capture.py
from __future__ import annotations
from scapy.all import sniff, Packet
from scapy.utils import PcapWriter
from time import strftime
from pathlib import Path
from threading import Event, Thread
from queue import Queue
from typing import Optional
from config import CAPTURE_DIR, BPF_FILTER

class PacketCapture:
    """
    Helpers for capturing packets with scapy.

    Explanation of technologies:
    - scapy.sniff: low-level packet capture and callback invocation for each packet.
    - PcapWriter: write packets to a pcap file incrementally (useful for large captures).
    - threading.Event / Thread: used for background capture and stopping.
    - Queue: used when streaming packets into a producer/consumer workflow.

    This class provides two modes:
    - capture_to_file: synchronous capture to a PCAP file with a progress indicator.
    - start_stream: background capture that pushes Packet objects into a Queue.
    """

    @staticmethod
    def _render_progress(current: int, total: int, width: int = 40) -> None:
        """Draw a simple in-terminal progress bar.

        - If total <= 0 (unbounded capture), print a simple counter.
        - If total > 0, show a filled bar with percentage.
        """
        if total <= 0:
            # for unbounded capture we show just a counter
            print(f"\rCaptured: {current} packets", end="", flush=True)
            return
        ratio = min(max(current / float(total), 0.0), 1.0)
        filled = int(width * ratio)
        bar = "█" * filled + "-" * (width - filled)
        print(f"\r[{bar}] {int(ratio * 100):3d}% ({current}/{total})", end="", flush=True)

    def __init__(self, iface_name: str, bpf: str = BPF_FILTER) -> None:
        # interface name to capture on and an optional BPF filter string
        self.iface = iface_name
        self.bpf = bpf

    def capture_to_file(self, count: int = 100000, prefix: str = "capture") -> Path:
        """
        Capture up to `count` packets to a PCAP while showing a CLI progress status.
        If count == 0 then capture until Ctrl+C (unbounded).
        Returns the Path to the saved pcap (may delete empty file if nothing captured).

        Notes:
        - CAPTURE_DIR is created if missing.
        - PcapWriter is opened with sync=True for safer writes on interrupts.
        """
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        fname = CAPTURE_DIR / f"{prefix}_{strftime('%Y%m%d_%H%M%S')}.pcap"

        writer = PcapWriter(str(fname), append=False, sync=True)
        captured = 0
        stop_event = Event()

        def _on_pkt(pkt: Packet):
            # Called by scapy for each captured packet.
            # We write to disk and update the counter. Any single-packet errors are ignored.
            nonlocal captured
            try:
                writer.write(pkt)
                captured += 1
                PacketCapture._render_progress(captured, count)
            except Exception:
                # don't stop capture on individual packet write errors
                pass

        try:
            # Informative CLI line: bounded captures print target count, unbounded instructs user to use Ctrl+C
            print(f"[info] starting capture on '{self.iface}' (filter='{self.bpf}') - press Ctrl+C to stop" if count == 0 else f"[info] capturing up to {count} packets on '{self.iface}'")
            sniff(
                iface=self.iface,
                filter=self.bpf,
                store=False,
                prn=_on_pkt,
                stop_filter=lambda p: (count > 0 and captured >= count) or stop_event.is_set()
            )
        except KeyboardInterrupt:
            # user pressed Ctrl+C — make shutdown explicit
            print("\n[info] stopping capture now and closing file. Please wait...")
            stop_event.set()
        except Exception as e:
            print(f"\n[err] capture error on {self.iface}: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

        # final render and summary
        if count:
            PacketCapture._render_progress(captured, count)
        else:
            # print newline for the counter line
            print()

        if captured:
            print(f"\n[ok] saved {captured} packets -> {fname}")
        else:
            # if user aborted very quickly we may have an empty file; attempt to clean it up
            try:
                if fname.exists() and fname.stat().st_size == 24:  # minimal pcap header length
                    fname.unlink(missing_ok=True)
                    print("[warn] no packets captured; removed empty file")
                else:
                    print("[warn] no packets captured; nothing written")
            except Exception:
                print("[warn] no packets captured; unable to clean up file")

        return fname

    def start_stream(self, packet_queue: Queue, stop_event: Event, store: bool = False) -> Thread:
        """
        Background thread capture that pushes packets into packet_queue.
        Use stop_event.set() to request stop.

        Parameters:
        - packet_queue: a queue.Queue instance where Packet objects will be put.
        - stop_event: threading.Event that signals termination.
        - store: if True, scapy will store packets in memory (not recommended for long runs).
        """
        def _prn(pkt: Packet) -> None:
            # Best-effort: try to put into queue without blocking to avoid blocking sniff thread.
            try:
                packet_queue.put(pkt, block=False)
            except Exception:
                # queue full or other error -> drop silently
                pass

        def _worker():
            # Worker function run inside the daemon thread.
            try:
                sniff(
                    iface=self.iface,
                    filter=self.bpf,
                    store=0 if not store else 1,
                    prn=_prn,
                    stop_filter=lambda p: stop_event.is_set()
                )
            except Exception as e:
                print(f"[err] capture error on {self.iface}: {e}")

        t = Thread(target=_worker, name="PacketCapture", daemon=True)
        t.start()
        return t


if __name__ == "__main__":
    # CLI helper: choose interface and capture; uses InterfaceManager.select() when iface omitted.
    import argparse
    from .if_manager import InterfaceManager
    from config import BPF_FILTER

    parser = argparse.ArgumentParser(description="Packet capture helper")
    parser.add_argument("--iface", help="Interface name to capture on (prompts if omitted)")
    parser.add_argument("--count", type=int, default=2000, help="Number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("--prefix", default="capture", help="Output pcap filename prefix")
    parser.add_argument("--filter", default=BPF_FILTER, help="BPF filter")
    args = parser.parse_args()

    iface_name = args.iface
    if not iface_name:
        # If no interface provided, prompt user to select one using interface helper.
        iface = InterfaceManager().select()
        iface_name = iface["name"]

    try:
        cap = PacketCapture(iface_name, bpf=args.filter)
        cap.capture_to_file(count=args.count, prefix=args.prefix)
    except KeyboardInterrupt:
        print("\n[info] capture interrupted by user.")
    except Exception as e:
        print(f"[err] capture failed: {e}")
