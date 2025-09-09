#!/usr/bin/env python3
"""
Orchestrator: capture -> parse -> (save | send)
Friendly interactive CLI + final summary for sending mode.
"""
from __future__ import annotations
import argparse
import sys
import json
import os
import shutil
from pathlib import Path
from queue import Queue
from threading import Event
import time

from sniffer.capture import PacketCapture
from sniffer.if_manager import InterfaceManager
from sniffer.parser import parse_pcap_to_flow_generator
from sniffer.sender_worker import SenderWorker
from sniffer.batch_sender import BatchSender
from config import CAPTURE_DIR, FLOW_RECORD_DIR, AUTH_TRANSPORT, DEFAULT_BATCH_SIZE, ALERTS_DIR

# === Banner Helpers ===
def _supports_color() -> bool:
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return True

def _ansi_rgb(r, g, b) -> str:
    return f"\x1b[38;2;{r};{g};{b}m"

def _ansi_reset() -> str:
    return "\x1b[0m"

def _center(line: str, width: int) -> str:
    line = line.rstrip("\n")
    pad = max(0, (width - len(line)) // 2)
    return " " * pad + line

def print_banner() -> None:
    cols = shutil.get_terminal_size((100, 24)).columns
    banner = r"""
   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                               . n  e  t
""".rstrip("\n")

    rule = "─" * min(80, max(40, cols - 10))
    lines = banner.splitlines()
    use_color = _supports_color()

    if use_color:
        start = (0, 230, 255)
        end   = (60, 120, 255)
        n = max(1, len(lines))
        colored = []
        for idx, raw in enumerate(lines):
            t = idx / max(1, n - 1)
            r = int(start[0] + (end[0] - start[0]) * t)
            g = int(start[1] + (end[1] - start[1]) * t)
            b = int(start[2] + (end[2] - start[2]) * t)
            colored.append(_ansi_rgb(r, g, b) + _center(raw, cols) + _ansi_reset())
        print("\n".join(colored))
        print(_ansi_rgb(120, 120, 140) + _center(rule, cols) + _ansi_reset())
    else:
        for raw in lines:
            print(_center(raw, cols))
        print(_center(rule, cols))
    print()


def choose_pcap_interactive() -> Path | None:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(CAPTURE_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        print("[info] No PCAPs in capture_logs. Choose 'Capture new pcap' to create one.")
        return None
    print("\nAvailable capture files (most recent first):")
    for i, p in enumerate(files, start=1):
        print(f"  {i}. {p.name} ({p.stat().st_size // 1024} KB)")
    print("  0. Capture new pcap now")
    while True:
        try:
            sel = int(input(f"Select pcap [0-{len(files)}]: ").strip())
            if 0 <= sel <= len(files):
                return None if sel == 0 else files[sel - 1]
        except ValueError:
            pass
        print("Invalid selection — enter a number.")

def ask_yes_no(prompt: str, default: bool = True) -> bool:
    yes_no = "Y/n" if default else "y/N"
    while True:
        ans = input(f"{prompt} [{yes_no}]: ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please answer y or n.")


def main():
    print_banner()   # <<< show banner first

    parser = argparse.ArgumentParser(description="sentinel.net orchestrator (capture -> parse -> save/send)")
    parser.add_argument("--capture", action="store_true", help="Start capture interactively")
    parser.add_argument("--iface", help="Interface to capture on (optional)")
    parser.add_argument("--count", type=int, default=0, help="Packets to capture (0 = until Ctrl+C)")
    parser.add_argument("--pcap", help="Path to pcap to process (skip capture step)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Batch size when sending to detector")
    args = parser.parse_args()

    # Step 1: either use provided pcap or capture/select one
    pcap_path: Path | None = None
    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            print(f"[err] pcap not found: {pcap_path}")
            sys.exit(1)
    else:
        if args.capture or ask_yes_no("Do you want to capture a new pcap now?", default=False):
            iface = args.iface
            if not iface:
                try:
                    iface = InterfaceManager().select()["name"]
                except Exception as e:
                    print(f"[err] Interface selection failed: {e}")
                    sys.exit(1)
            cap = PacketCapture(iface)
            print(f"[info] Starting capture on {iface}. Ctrl+C to stop.")
            pcap_path = cap.capture_to_file(count=args.count or 0)
        else:
            chosen = choose_pcap_interactive()
            if chosen is None:
                iface = args.iface or InterfaceManager().select()["name"]
                cap = PacketCapture(iface)
                pcap_path = cap.capture_to_file(count=args.count or 0)
            else:
                pcap_path = chosen

    if not pcap_path or not pcap_path.exists():
        print("[err] No pcap available. Exiting.")
        sys.exit(1)

    print(f"\n[info] Selected PCAP: {pcap_path.name} ({pcap_path.stat().st_size // 1024} KB)")

    # Step 2: ask Save or Send
    print("\nOptions:\n  1) Save flow records locally (default)\n  2) Send flows directly to detector (requires DESCOPE and detector reachable)")
    send_now = ask_yes_no("Send flows to detector now? (choose No to save locally)", default=False)

    FLOW_RECORD_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FLOW_RECORD_DIR / f"{pcap_path.stem}_flow.jsonl"

    if send_now and AUTH_TRANSPORT != "http":
        print("[warn] HTTP/Descope transport is not enabled in config; falling back to saving locally.")
        send_now = False

    batch_size = max(1, int(args.batch_size))
    if batch_size > 2000:
        print(f"[warn] Batch size {batch_size} is large — consider using smaller value (64-512) for lower latency.")
    print(f"[info] Parsing PCAP -> flows (expiry={args.count if args.count else 'default'})  Batch size={batch_size}")

    sender: SenderWorker | None = None
    queue = None

    if send_now:
        queue = Queue(maxsize=10000)
        batch_sender = BatchSender()
        sender = SenderWorker(queue, batch_sender, batch_size=batch_size, out_path=str(out_path))
        sender.start()
        print("[info] Sender worker started and will stream flows to detector. You will get a summary when finished.")

    saved_local = 0
    streamed = 0
    fallback_saved = 0

    try:
        gen = parse_pcap_to_flow_generator(pcap_path)
        fh = None if send_now else out_path.open("a", encoding="utf-8")
        for rec in gen:
            if send_now and sender:
                try:
                    queue.put(rec, timeout=5)
                    streamed += 1
                except Exception:
                    print("[warn] send queue full or unavailable — persisting this flow to disk")
                    if fh is None:
                        fh = out_path.open("a", encoding="utf-8")
                    fh.write(json.dumps(rec) + "\n")
                    fallback_saved += 1
            else:
                if fh is None:
                    fh = out_path.open("a", encoding="utf-8")
                fh.write(json.dumps(rec) + "\n")
                saved_local += 1
        if fh:
            fh.flush()
            fh.close()
    except KeyboardInterrupt:
        print("\n[info] Parsing interrupted by user.")
    except Exception as e:
        print(f"[err] Parsing failed: {e}")
    finally:
        if send_now and sender:
            print("[info] Parsing finished — waiting for sender worker to drain queued flows...")
            sender.stop()
            wait_start = time.time()
            while True:
                elapsed = time.time() - wait_start
                flows_sent = sender.flows_sent
                batches_sent = sender.batches_sent
                batches_failed = sender.batches_failed
                alerts_generated = sender.alerts_generated
                queued = queue.qsize() if queue is not None else 0
                s = (f"\r[progress] queued={queued} sent={flows_sent} "
                     f"batches={batches_sent} failed={batches_failed} alerts={alerts_generated}  ")
                sys.stdout.write(s)
                sys.stdout.flush()
                if not sender.is_alive() and queued == 0:
                    break
                time.sleep(0.8)
            print()
            sender.join(timeout=5)
            stats = {
                "flows_streamed_into_queue": streamed,
                "flows_sent": sender.flows_sent,
                "batches_sent": sender.batches_sent,
                "batches_failed": sender.batches_failed,
                "alerts_generated": sender.alerts_generated,
            }
            print("\n=== SEND SESSION SUMMARY ===")
            print(f"Flows enqueued for sending: {stats['flows_streamed_into_queue']}")
            print(f"Flows successfully sent to detector: {stats['flows_sent']}")
            print(f"Batches sent: {stats['batches_sent']}  Batches failed: {stats['batches_failed']}")
            if stats["alerts_generated"] > 0:
                print(f"Detector reported total alerts (aggregated from responses): {stats['alerts_generated']}")
            else:
                print("Detector did not report alert counts in HTTP responses (server may still have written alerts to disk).")
                print(f"Check detector alerts directory: {ALERTS_DIR} for per-batch alert files and detector logs.")
            print("=============================\n")
        else:
            print(f"\n[ok] Flows saved locally to: {out_path}  (count saved ≈ {saved_local + fallback_saved})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
