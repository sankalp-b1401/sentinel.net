#!/usr/bin/env python3
"""
transport_http.py

Simple HTTP transport helper used by BatchSender or other test code to POST
flows to the detector API. This module is a lightweight, standalone function
set that can be used in scripts or unit tests.

Behavior summary:
 - Uses descope_client.get_service_token() for bearer token when token param is None.
 - Posts JSON payload to DETECTOR_URL + "/api/v1/flows".
 - On 401 will refresh token once and retry (configurable via max_retries).
 - Returns tuple (ok: bool, resp_json_or_text: dict|str|None, status_code: int)
 - Does not raise for network errors; returns False with error details instead.
"""

from __future__ import annotations
import json
import time
import logging
from typing import Iterable, Optional, Tuple, Any, Dict
from urllib.parse import urljoin

import requests

from config import DETECTOR_URL, TRANSPORT_TIMEOUT
from auth.descope_client import get_service_token

log = logging.getLogger("transport_http")
DEFAULT_TIMEOUT = int(TRANSPORT_TIMEOUT or 15)

def _build_payload(flows: Iterable[dict], session_id: Optional[str] = None, meta: Optional[dict] = None) -> Any:
    """
    Build the JSON-serializable payload.

    - If session_id provided, return an object: {"session_id":..., "flows":[...], "meta":...}
    - Otherwise return legacy behavior: a plain list of flow dicts.
    """
    flows_list = list(flows)
    if session_id:
        payload: Dict[str, Any] = {"session_id": str(session_id), "flows": flows_list}
        if meta:
            payload["meta"] = meta
        return payload
    # legacy behaviour: send list directly
    return flows_list

def send_batch_http(
    flows: Iterable[dict],
    detector_url: Optional[str] = None,
    session_id: Optional[str] = None,
    meta: Optional[dict] = None,
    token: Optional[str] = None,
    timeout: Optional[int] = None,
    max_retries: int = 2,
) -> Tuple[bool, Optional[Any], int]:
    """
    Send a batch of flows to detector HTTP endpoint.

    Returns:
      (ok, response_json_or_text_or_none, status_code)

    Notes:
    - If token argument is None, will try to fetch a token via get_service_token().
    - On 401 status, will attempt to refresh token once and retry (subject to max_retries).
    - Network errors return (False, error_string, 0) or the HTTP status if available.
    """
    detector_url = (detector_url or DETECTOR_URL).rstrip("/")
    url = urljoin(detector_url + "/", "api/v1/flows")
    timeout = timeout or DEFAULT_TIMEOUT

    payload = _build_payload(flows, session_id=session_id, meta=meta)
    headers = {"Content-Type": "application/json"}

    # request loop: attempt to refresh token on 401 once
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            if not token:
                try:
                    token = get_service_token()
                except Exception as e:
                    # return false with explanatory message; do not raise for network flows
                    err = f"failed to obtain service token: {e}"
                    log.exception(err)
                    return False, err, 0
            headers["Authorization"] = f"Bearer {token}"
            resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
            status = resp.status_code
            # On success-ish (2xx), return parsed JSON if available
            if 200 <= status < 300:
                try:
                    return True, resp.json(), status
                except Exception:
                    # If JSON parse fails, return raw text
                    return True, resp.text, status
            # If unauthorized, try refreshing token once more (but only one extra attempt)
            if status == 401 and attempt < max_retries:
                log.warning("send_batch_http: 401 from server, refreshing token and retrying (attempt %d)", attempt)
                try:
                    token = get_service_token()
                except Exception as e:
                    last_exc = e
                    log.exception("failed to refresh service token: %s", e)
                    return False, f"token refresh failed: {e}", 401
                # loop will retry
                continue
            # other non-2xx status: try decode error JSON for helpful debug info
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            log.warning("send_batch_http: server returned status %d: %s", status, str(body)[:200])
            return False, body, status
        except requests.exceptions.RequestException as e:
            # Handle network-level errors like connection timeouts, DNS errors etc.
            last_exc = e
            log.warning("send_batch_http attempt %d failed: %s", attempt, repr(e))
            # small backoff before retrying
            time.sleep(0.5 * attempt)
            continue
        except Exception as e:
            # Unexpected programming error: log and return failure tuple
            last_exc = e
            log.exception("send_batch_http unexpected error: %s", e)
            return False, str(e), 0

    # exhausted retries without success
    err_msg = f"send_batch_http failed after {max_retries} attempts: {repr(last_exc)}"
    log.error(err_msg)
    return False, err_msg, 0

# Convenience wrapper to raise on failure for callers that prefer exceptions
def send_batch_http_strict(*args, **kwargs) -> Any:
    ok, body, status = send_batch_http(*args, **kwargs)
    if not ok:
        raise RuntimeError(f"send_batch_http failed status={status} body={body}")
    return body
