#!/usr/bin/env python3
"""
Orchestrator: capture -> parse -> (save | send)
Friendly interactive CLI + final summary for sending mode.
"""
from __future__ import annotations
import argparse
import sys
import json
from pathlib import Path
from queue import Queue
import time
import uuid
import requests
from auth.descope_client import get_service_token

# UI / banner helpers (centralized)
from ui import (
    print_banner,
    info,
    warn,
    err,
    ok,
    ask_yes_no,
    select_pcap_interactive,
    human_size,
)

from sniffer.capture import PacketCapture
from sniffer.if_manager import InterfaceManager
from sniffer.parser import parse_pcap_to_flow_generator
from sniffer.sender_worker import SenderWorker
from sniffer.batch_sender import BatchSender
from config import CAPTURE_DIR, FLOW_RECORD_DIR, AUTH_TRANSPORT, DEFAULT_BATCH_SIZE, ALERTS_DIR, DETECTOR_URL


def main():
    print_banner()   # show banner first

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
            err(f"pcap not found: {pcap_path}")
            sys.exit(1)
    else:
        if args.capture or ask_yes_no("Do you want to capture a new pcap now?", default=False):
            iface = args.iface
            if not iface:
                try:
                    iface = InterfaceManager().select()["name"]
                except Exception as e:
                    err(f"Interface selection failed: {e}")
                    sys.exit(1)
            cap = PacketCapture(iface)
            info(f"Starting capture on {iface}. Ctrl+C to stop.")
            pcap_path = cap.capture_to_file(count=args.count or 0)
        else:
            chosen = select_pcap_interactive(CAPTURE_DIR)
            if chosen is None:
                iface = args.iface or InterfaceManager().select()["name"]
                cap = PacketCapture(iface)
                pcap_path = cap.capture_to_file(count=args.count or 0)
            else:
                pcap_path = chosen

    if not pcap_path or not pcap_path.exists():
        err("No pcap available. Exiting.")
        sys.exit(1)

    info(f"Selected PCAP: {pcap_path.name} ({human_size(pcap_path.stat().st_size)})")

    # Step 2: ask Save or Send
    # print plain text header then use ask_yes_no which uses colored prompt
    print("\n[?] Options")
    print("  1) Save flow records locally (default)")
    print("  2) Send flows directly to detector (requires DESCOPE and detector reachable)")
    send_now = ask_yes_no("Send flows to detector now? (choose No to save locally)", default=False)

    FLOW_RECORD_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FLOW_RECORD_DIR / f"{pcap_path.stem}_flow.jsonl"

    if send_now and AUTH_TRANSPORT != "http":
        warn("HTTP/Descope transport is not enabled in config; falling back to saving locally.")
        send_now = False

    batch_size = max(1, int(args.batch_size))
    if batch_size > 2000:
        warn(f"Batch size {batch_size} is large — consider using smaller value (64-512) for lower latency.")
    info(f"Parsing PCAP -> flows (expiry={args.count if args.count else 'default'})  Batch size={batch_size}")

    sender: SenderWorker | None = None
    queue = None

    if send_now:
        queue = Queue(maxsize=10000)
        batch_sender = BatchSender()
        # create a session id (client FIN will trigger server to aggregate)
        session_id = str(uuid.uuid4())
        sender = SenderWorker(queue, batch_sender, batch_size=batch_size, out_path=str(out_path), session_id=session_id)
        sender.start()
        info("Sender worker started and will stream flows to detector. You will get a summary when finished.")

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
                    warn("send queue full or unavailable — persisting this flow to disk")
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
        info("Parsing interrupted by user.")
    except Exception as e:
        err(f"Parsing failed: {e}")
    finally:
        if send_now and sender:
            info("Parsing finished — waiting for sender worker to drain queued flows...")
            sender.stop()
            wait_start = time.time()
            while True:
                flows_sent = sender.flows_sent
                batches_sent = sender.batches_sent
                batches_failed = sender.batches_failed
                queued = queue.qsize() if queue is not None else 0
                s = (f"\r[progress] queued={queued} sent={flows_sent} "
                     f"batches={batches_sent} failed={batches_failed} ")
                sys.stdout.write(s)
                sys.stdout.flush()
                if not sender.is_alive() and queued == 0:
                    break
                time.sleep(0.8)
            print()
            
            sender.join(timeout=5)

            # --- authenticated finalize + status polling ---
            session_status = {"status": "pending"}
            if send_now and sender and getattr(sender, "session_id", None):
                finalize_url = f"{DETECTOR_URL.rstrip('/')}/api/v1/sessions/{sender.session_id}/finalize"
                status_url = f"{DETECTOR_URL.rstrip('/')}/api/v1/sessions/{sender.session_id}/status"

                # obtain service token (may raise/return None on failure)
                token = None
                try:
                    token = get_service_token()
                except Exception as e:
                    warn(f"failed to obtain service token for session finalize/status: {e}")
                    token = None

                headers = {"Authorization": f"Bearer {token}"} if token else {}

                # Send finalize (authenticated if token available)
                try:
                    fr = requests.post(finalize_url, timeout=5.0, headers=headers)
                    if fr.status_code not in (200, 202):
                        # if 401 received and we have no token, warn about auth
                        if fr.status_code == 401:
                            warn(f"session finalize returned 401: missing Authorization Bearer token or token rejected")
                        else:
                            warn(f"session finalize returned {fr.status_code}: {fr.text}")
                except Exception as e:
                    warn(f"session finalize failed: {e}")

                # Poll for final status with a spinner (include same headers)
                spinner = "|/-\\"
                messages = ["Analysing logs.", "Generating alerts."]
                start_t = time.time()
                spin_i = 0
                msg_i = 0
                SESSION_WAIT_TIMEOUT = 120.0  # tune as needed
                while True:
                    try:
                        sr = requests.get(status_url, timeout=5.0, headers=headers)
                        if sr.status_code == 200:
                            session_status = sr.json()
                            st = session_status.get("status", "pending")
                            if st in ("done", "failed"):
                                break
                        elif sr.status_code == 401:
                            # auth failure while polling
                            warn("session status returned 401: missing/invalid Authorization token")
                            # If we had no token, try to fetch one now and retry requests with it
                            if not token:
                                try:
                                    token = get_service_token()
                                    headers = {"Authorization": f"Bearer {token}"}
                                    warn("obtained service token; continuing status polling with Authorization header")
                                except Exception as e:
                                    warn(f"failed to obtain service token while polling status: {e}")
                                    # keep polling without token in case server accepts anonymous (unlikely)
                            # continue; allow timeout to eventually break
                        else:
                            # non-200 non-401: ignore and continue until timeout
                            pass
                    except Exception:
                        # network or transient error; just continue until timeout
                        pass

                    elapsed = time.time() - start_t
                    if elapsed >= SESSION_WAIT_TIMEOUT:
                        session_status = {"status": "timeout", "elapsed": elapsed}
                        break

                    # spinner update
                    try:
                        sys.stdout.write(f"\r[{spinner[spin_i % len(spinner)]}] {messages[msg_i % len(messages)]} elapsed={elapsed:.1f}s ")
                        sys.stdout.flush()
                    except Exception:
                        pass
                    spin_i += 1
                    if spin_i % 20 == 0:
                        msg_i += 1
                    time.sleep(0.25)

                # clear spinner line
                try:
                    sys.stdout.write("\r" + " " * 120 + "\r")
                    sys.stdout.flush()
                except Exception:
                    pass
            # --- end authenticated finalize + status ---


            # Prepare stats (sender counters still reflect HTTP responses; session_status has authoritative final counts)
            stats = {
                "flows_streamed_into_queue": streamed,
                "flows_sent": sender.flows_sent if sender else 0,
                "batches_sent": sender.batches_sent if sender else 0,
                "batches_failed": sender.batches_failed if sender else 0,
                "alerts_generated_http": sender.alerts_generated if sender else 0,
            }

            print("\n=== SEND SESSION SUMMARY ===")
            if send_now and sender and getattr(sender, "session_id", None):
                print(f"Session id: {sender.session_id}")
            print(f"Flows enqueued for sending: {stats['flows_streamed_into_queue']}")
            print(f"Flows successfully sent to detector: {stats['flows_sent']}")
            print(f"Batches sent: {stats['batches_sent']}  Batches failed: {stats['batches_failed']}")

            st = session_status.get("status")
            if st == "done":
                print(f"Detector reported total alerts for session: {session_status.get('alerts_count', 0)}")
                print(f"Detector reported batch_count: {session_status.get('batch_count', 0)}")
                print(f"Detector reported flow_count: {session_status.get('flow_count', 0)}")
                if session_status.get("alerts_path"):
                    print(f"Detector alerts file: {session_status.get('alerts_path')}")
            elif st == "timeout":
                print("Detector processing did not finish within wait timeout.")
                print("You may check detector status directory or alerts directory for results.")
                print(f"Alarms found in HTTP responses so far (best-effort): {stats['alerts_generated_http']}")
            elif st == "failed":
                print("Detector reported failure while processing session.")
                print("See server status for details:", session_status.get("error"))
            else:
                # fallback: if no session info, still show best-effort HTTP-aggregated alerts
                if stats["alerts_generated_http"] > 0:
                    print(f"Detector reported total alerts (from HTTP responses): {stats['alerts_generated_http']}")
                else:
                    print("Detector did not report final status. Check alerts dir and server logs.")

            print("=============================\n")

        else:
            ok(f"Flows saved locally to: {out_path}  (count saved ≈ {saved_local + fallback_saved})")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n")
        info("Program ended by user (Ctrl+C).")
        sys.exit(0)
