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
    Background sender thread that reads flow dicts from a Queue and sends them to the detector in batches.

    Responsibilities:
    - Collect items from a queue.
    - Send them in batches via BatchSender.
    - Persist failed flows to disk if provided an out_path.
    - Keep simple send statistics for reporting.

    Use pattern:
    - Create q = Queue()
    - worker = SenderWorker(q, BatchSender(), batch_size=64, out_path="failed.jsonl")
    - worker.start()
    - push flow dicts into q
    - call worker.stop() and worker.join() when finished to flush and close cleanly.
    """

    def __init__(self, q: Queue, batch_sender: BatchSender, batch_size: int = 64,
                 out_path: Optional[str] = None, poll_timeout: float = 1.0, session_id: str | None = None):
        super().__init__(daemon=True, name="SenderWorker")
        self.q = q
        self.batch_sender = batch_sender
        self.batch_size = max(1, batch_size)
        self.poll_timeout = float(poll_timeout)
        self._stop_event = threading.Event()
        self._stopped_event = threading.Event()
        self.out_path = out_path
        self.session_id = session_id

        # statistics to understand activity after run
        self.flows_sent = 0
        self.batches_sent = 0
        self.batches_failed = 0
        self.alerts_generated = 0  # aggregated from server responses (best-effort)

    def stop(self):
        """Signal the worker to finish processing and exit gracefully."""
        self._stop_event.set()

    def join(self, timeout: float = None):
        """
        Wait for the worker to signal it has stopped and then ensure BatchSender resources closed.
        Note: overrides Thread.join signature for convenience; actual waiting is on an internal event.
        """
        self._stopped_event.wait(timeout)
        try:
            self.batch_sender.close()
        except Exception:
            pass

    def _persist_failed(self, flows: List[dict]):
        """
        Append failed flows to out_path as newline-delimited JSON (JSONL).
        If no out_path configured, do nothing.
        """
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

        The detector may return:
        - a dict with keys like 'alerts' (list) or 'alert_count' (int)
        - a list of alerts
        - nested results under 'result'
        We inspect common keys and attempt to return an integer count.
        """
        try:
            if not resp_obj:
                return 0
            if isinstance(resp_obj, dict):
                for key in ("alerts", "anomalies", "alert_count", "num_alerts", "count"):
                    if key in resp_obj:
                        v = resp_obj[key]
                        if isinstance(v, int):
                            return v
                        if isinstance(v, list):
                            return len(v)
                        if isinstance(v, str) and v.isdigit():
                            return int(v)
                # nested result objects sometimes hold the interesting value
                if "result" in resp_obj and isinstance(resp_obj["result"], dict):
                    return self._extract_alert_count(resp_obj["result"])
            elif isinstance(resp_obj, list):
                return len(resp_obj)
        except Exception:
            # best-effort: if extraction fails, return 0
            pass
        return 0

    def run(self):
        """
        Main loop:
        - Pull items from queue until stop event set and queue empty.
        - Accumulate into a batch and send when full or when stopping.
        - Persist failed batches to disk.
        - Maintain counters for monitoring.
        """
        batch: List[dict] = []
        while not self._stop_event.is_set() or not self.q.empty():
            try:
                # Poll queue with timeout so we can notice stop_event periodically
                item = self.q.get(timeout=self.poll_timeout)
            except Empty:
                item = None

            if item is not None:
                batch.append(item)

            # Decide whether to send based on size or stopping condition
            should_send = False
            if len(batch) >= self.batch_size:
                should_send = True
            elif self._stop_event.is_set() and batch:
                should_send = True

            if should_send and batch:
                try:
                    ok, resp_obj, failed = self.batch_sender.send_batch(batch, session_id=self.session_id)
                    if ok:
                        # Successful send: update counters and try to extract alert count from server response
                        self.batches_sent += 1
                        sent_len = len(batch)
                        self.flows_sent += sent_len
                        alerts_here = self._extract_alert_count(resp_obj)
                        self.alerts_generated += alerts_here
                        log.info("Sent batch size=%d; server_alerts=%d", sent_len, alerts_here)
                    else:
                        # send failed: increment failed counter and persist failed flows
                        self.batches_failed += 1
                        if failed:
                            self._persist_failed(failed)
                            log.warning("Persisted %d failed flows to %s", len(failed), self.out_path)
                except Exception as e:
                    # Unexpected error: persist the whole batch and log exception
                    self.batches_failed += 1
                    try:
                        self._persist_failed(batch)
                    except Exception:
                        pass
                    log.exception("Unhandled exception when sending batch: %s", e)
                finally:
                    batch = []

        # final cleanup: ensure any leftover flows are attempted to be sent once more
        if batch:
            try:
                ok, resp_obj, failed = self.batch_sender.send_batch(batch, session_id=self.session_id)
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

        # Signal that we've fully stopped and cleaned up
        self._stopped_event.set()
