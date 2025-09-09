# sniffer/sender_worker.py
from __future__ import annotations
import threading
import time
import json
import logging
from queue import Queue, Empty
from typing import Optional, List, Dict, Any
from sniffer.batch_sender import BatchSender

log = logging.getLogger("sniffer.sender_worker")
log.setLevel(logging.INFO)


class SenderWorker(threading.Thread):
    """
    Background sender that reads flows from a Queue and sends them in batches.
    It collects counters to allow a final report: flows_sent, batches_sent, batches_failed, alerts_generated.
    """

    def __init__(self, q: Queue, batch_sender: BatchSender, batch_size: int = 64,
                 out_path: Optional[str] = None, poll_timeout: float = 1.0):
        super().__init__(daemon=True, name="SenderWorker")
        self.q = q
        self.batch_sender = batch_sender
        self.batch_size = max(1, batch_size)
        self.poll_timeout = float(poll_timeout)
        self._stop_event = threading.Event()
        self._stopped_event = threading.Event()
        self.out_path = out_path

        # statistics
        self.flows_sent = 0
        self.batches_sent = 0
        self.batches_failed = 0
        self.alerts_generated = 0  # aggregated from server responses (best-effort)

    def stop(self):
        """Signal the worker to finish processing and exit."""
        self._stop_event.set()

    def join(self, timeout: float = None):
        self._stopped_event.wait(timeout)
        try:
            self.batch_sender.close()
        except Exception:
            pass

    def _persist_failed(self, flows: List[dict]):
        if not self.out_path:
            return
        try:
            with open(self.out_path, "a", encoding="utf-8") as fh:
                for f in flows:
                    fh.write(json.dumps(f) + "\n")
        except Exception as e:
            log.error("Failed to persist failed flows to %s: %s", self.out_path, e)

    def _extract_alert_count(self, resp_obj: Any) -> int:
        """
        Try to extract an alert count from the detector response body.
        Looks for common keys: 'alerts', 'anomalies', 'alert_count', 'num_alerts', 'count'
        Accepts either a list (len) or int value.
        """
        try:
            if not resp_obj:
                return 0
            if isinstance(resp_obj, dict):
                # common keys
                for key in ("alerts", "anomalies", "alert_count", "num_alerts", "count"):
                    if key in resp_obj:
                        v = resp_obj[key]
                        if isinstance(v, int):
                            return v
                        if isinstance(v, list):
                            return len(v)
                        if isinstance(v, str) and v.isdigit():
                            return int(v)
                # nested: maybe resp_obj.get("result", {...})
                if "result" in resp_obj and isinstance(resp_obj["result"], dict):
                    return self._extract_alert_count(resp_obj["result"])
            elif isinstance(resp_obj, list):
                return len(resp_obj)
        except Exception:
            pass
        return 0

    def run(self):
        batch: List[dict] = []
        while not self._stop_event.is_set() or not self.q.empty():
            try:
                item = self.q.get(timeout=self.poll_timeout)
            except Empty:
                item = None

            if item is not None:
                batch.append(item)

            # Send when batch full or when stopping and we have leftover
            should_send = False
            if len(batch) >= self.batch_size:
                should_send = True
            elif self._stop_event.is_set() and batch:
                should_send = True

            if should_send and batch:
                try:
                    ok, resp_obj, failed = self.batch_sender.send_batch(batch)
                    if ok:
                        self.batches_sent += 1
                        sent_len = len(batch)
                        self.flows_sent += sent_len
                        # try to extract alerts_count from response
                        alerts_here = self._extract_alert_count(resp_obj)
                        self.alerts_generated += alerts_here
                        log.info("Sent batch size=%d; server_alerts=%d", sent_len, alerts_here)
                    else:
                        self.batches_failed += 1
                        # persist failed flows to disk so they are not lost
                        if failed:
                            self._persist_failed(failed)
                            log.warning("Persisted %d failed flows to %s", len(failed), self.out_path)
                except Exception as e:
                    self.batches_failed += 1
                    # persist the whole batch if an unexpected exception occurred
                    try:
                        self._persist_failed(batch)
                    except Exception:
                        pass
                    log.exception("Unhandled exception when sending batch: %s", e)
                finally:
                    batch = []

        # final cleanup: send any remaining flows if present
        if batch:
            try:
                ok, resp_obj, failed = self.batch_sender.send_batch(batch)
                if ok:
                    self.batches_sent += 1
                    sent_len = len(batch)
                    self.flows_sent += sent_len
                    alerts_here = self._extract_alert_count(resp_obj)
                    self.alerts_generated += alerts_here
                    log.info("Final send: size=%d; server_alerts=%d", sent_len, alerts_here)
                else:
                    self.batches_failed += 1
                    if failed:
                        self._persist_failed(failed)
                        log.warning("Persisted %d failed flows to %s (final)", len(failed), self.out_path)
            except Exception as e:
                self.batches_failed += 1
                try:
                    self._persist_failed(batch)
                except Exception:
                    pass
                log.exception("Unhandled exception when sending final batch: %s", e)

        self._stopped_event.set()
