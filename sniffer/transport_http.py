import requests
import os
from auth.descope_client import get_service_token
from config import DETECTOR_URL, TRANSPORT_TIMEOUT

def send_batch_http(flows, detector_url=None):
    detector_url = detector_url or os.getenv("DETECTOR_URL", "http://127.0.0.1:8443")
    token = get_service_token()
    # DEBUG: print token (or first 80 chars)
    print("[debug] token (truncated):", token[:120] + "..." if token and len(token) > 120 else token)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.post(detector_url.rstrip("/") + "/api/v1/flows", json=flows, headers=headers, timeout=15)
    print("[debug] server response status:", r.status_code)
    print("[debug] server response text:", r.text)
    r.raise_for_status()
    return r.json()