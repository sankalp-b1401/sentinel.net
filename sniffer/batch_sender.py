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

    Explanation of technologies:
    - requests.Session: keeps HTTP connection parameters and connection pooling,
      so repeated POSTs are faster and headers/cookies can be reused.
    - descope_client.get_service_token(): external helper that should return
      a Bearer token string for authenticating to the detector API.
    - DETECTOR_URL, TRANSPORT_TIMEOUT: configuration constants from your config.
    """

    def __init__(self, detector_url: Optional[str] = None, timeout: int = TRANSPORT_TIMEOUT):
        # Build detector URL; fallback to a sensible local URL if not configured.
        self.detector_url = (detector_url or DETECTOR_URL or "http://127.0.0.1:8443").rstrip("/")
        # HTTP session for connection reuse and headers management
        self.session = requests.Session()
        # timeout used for requests.post calls
        self.timeout = timeout if timeout is not None else 15
        # cached token and metadata for conservative TTL handling
        self._token = None
        self._token_acquired_at = 0
        self._token_ttl = 300  # seconds; conservative TTL. We refresh on 401 or after TTL expires
        # Ensure requests uses a sensible User-Agent; content-type is set per request.
        self.session.headers.update({"User-Agent": "sentinel.net-sniffer/1.0"})

    def _ensure_token(self, force_refresh: bool = False) -> str:
        """Call get_service_token() to fetch a fresh token if needed.

        Logic:
        - If token missing or forced refresh or TTL expired, call get_service_token.
        - If token retrieval fails, raise a RuntimeError (caller will handle).
        """
        if self._token is None or force_refresh or (time.time() - self._token_acquired_at) > self._token_ttl:
            token = get_service_token()
            if not token:
                raise RuntimeError("Failed to obtain service token")
            self._token = token
            self._token_acquired_at = time.time()
        return self._token

    def _post(self, path: str, json_body, headers=None):
        """Low-level POST helper using the session."""
        url = f"{self.detector_url}{path}"
        return self.session.post(url, json=json_body, headers=headers, timeout=self.timeout)

    def send_batch(self, flows: Iterable[dict], batch_retries: int = DEFAULT_BATCH_RETRIES,
                   session_id: str | None = None, meta: dict | None = None) -> Tuple[bool, Optional[dict], Optional[List[dict]]]:
        """
        Send flows to detector. If session_id provided, POST payload={"session_id":..., "flows":[...], "meta":...}
        Returns (ok, server_json_or_none, failed_batch_or_none)

        Important behaviour notes:
        - Converts flows iterable into a list once so we can retry and possibly persist it on failure.
        - On 401 response the token is cleared and we retry (force refresh).
        - On other exceptions we back off and retry up to batch_retries.
        - On success returns True and parsed JSON (or text fallback).
        - On exhaustion returns False and the original flows list as 'failed'.
        """
        flows_list = list(flows)
        if not flows_list:
            # nothing to send
            return True, {}, None

        # build payload: either list (legacy) or object with session_id/meta (recommended)
        if session_id:
            payload = {"session_id": session_id, "flows": flows_list}
            if meta:
                payload["meta"] = meta
        else:
            payload = flows_list

        last_exc = None
        for attempt in range(1, batch_retries + 1):
            try:
                # Acquire token, optionally forcing refresh on subsequent attempts
                token = self._ensure_token(force_refresh=(attempt > 1))
                headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
                resp = self._post("/api/v1/flows", payload, headers=headers)

                # If the server rejects authorization, try refreshing token and retry
                if resp.status_code == 401:
                    log.warning("server returned 401; refreshing token and retrying (attempt %d)", attempt)
                    self._token = None
                    last_exc = RuntimeError(f"server returned 401: {resp.text}")
                    time.sleep(BATCH_BACKOFF * attempt)
                    continue

                # Raise for other HTTP error statuses (4xx/5xx)
                resp.raise_for_status()

                # Try to parse JSON result; if it fails return text in a dict
                try:
                    body = resp.json()
                except Exception:
                    body = {"status": "ok", "text": resp.text}
                return True, body, None

            except Exception as e:
                # Network error, JSON error, requests exception, or unexpected runtime error.
                last_exc = e
                log.warning("send_batch attempt %d failed: %s", attempt, repr(e))
                time.sleep(BATCH_BACKOFF * attempt)

        log.error("send_batch failed after %d attempts: %s", batch_retries, repr(last_exc))
        # On overall failure return the flows so caller can persist them if needed.
        return False, None, flows_list

    def close(self):
        """Close the HTTP session; ignore errors during close."""
        try:
            self.session.close()
        except Exception:
            pass
