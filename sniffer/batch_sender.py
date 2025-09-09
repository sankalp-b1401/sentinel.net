# sniffer/batch_sender.py
from __future__ import annotations
import time
import json
import logging
from typing import Iterable, List, Optional, Tuple
import requests
from auth.descope_client import get_service_token  # existing helper you have
from config import DETECTOR_URL, TRANSPORT_TIMEOUT

log = logging.getLogger("sniffer.batch_sender")
DEFAULT_BATCH_RETRIES = 3
BATCH_BACKOFF = 0.5

class BatchSender:
    """
    Manage an HTTP session and a single auth token for a sending session.
    Use send_batch(flows) to send a list of flow dicts (JSON-serializable).
    """

    def __init__(self, detector_url: Optional[str] = None, timeout: int = TRANSPORT_TIMEOUT):
        self.detector_url = (detector_url or DETECTOR_URL or "http://127.0.0.1:8443").rstrip("/")
        self.session = requests.Session()
        self.timeout = timeout if timeout is not None else 15
        self._token = None
        self._token_acquired_at = 0
        self._token_ttl = 300  # conservative TTL; we'll refresh on 401 or after TTL
        # ensure headers content-type set by request, not global
        self.session.headers.update({"User-Agent": "sentinel.net-sniffer/1.0"})

    def _ensure_token(self, force_refresh: bool = False) -> str:
        """Call get_service_token() to fetch a fresh token if needed."""
        if self._token is None or force_refresh or (time.time() - self._token_acquired_at) > self._token_ttl:
            token = get_service_token()
            if not token:
                raise RuntimeError("Failed to obtain service token")
            self._token = token
            self._token_acquired_at = time.time()
        return self._token

    def _post(self, path: str, json_body, headers=None):
        url = f"{self.detector_url}{path}"
        return self.session.post(url, json=json_body, headers=headers, timeout=self.timeout)

    def send_batch(self, flows: Iterable[dict], batch_retries: int = DEFAULT_BATCH_RETRIES) -> Tuple[bool, Optional[dict], Optional[List[dict]]]:
        """
        Send flows to detector. Returns (ok, server_json_or_none, failed_batch_or_none)
        If ok: server_json returned, failed_batch is None.
        If not ok: server_json may be None and failed_batch contains flows that should be persisted.
        """
        flows_list = list(flows)
        if not flows_list:
            return True, {}, None

        # get token and try
        last_exc = None
        for attempt in range(1, batch_retries + 1):
            try:
                token = self._ensure_token(force_refresh=(attempt > 1))
                headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
                resp = self._post("/api/v1/flows", flows_list, headers=headers)
                # If we get 401, try refresh token once
                if resp.status_code == 401:
                    log.warning("server returned 401; refreshing token and retrying (attempt %d)", attempt)
                    # force token refresh next loop iteration
                    self._token = None
                    last_exc = RuntimeError(f"server returned 401: {resp.text}")
                    time.sleep(BATCH_BACKOFF * attempt)
                    continue
                resp.raise_for_status()
                # success
                try:
                    body = resp.json()
                except Exception:
                    body = {"status": "ok", "text": resp.text}
                return True, body, None
            except Exception as e:
                last_exc = e
                log.warning("send_batch attempt %d failed: %s", attempt, repr(e))
                time.sleep(BATCH_BACKOFF * attempt)

        # final: failed after retries — return failed batch for caller to persist
        log.error("send_batch failed after %d attempts: %s", batch_retries, repr(last_exc))
        return False, None, flows_list

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass
