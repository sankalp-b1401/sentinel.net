# auth/descope_client.py
"""
Small helper for obtaining a service token to call the detector HTTP API.
Prefer SERVICE_JWT env var in dev. In production you likely mint short-lived tokens
via a secure backend and store them in env/vault.
"""
import time
import requests
from config import SERVICE_JWT, DESCOPE_TOKEN_ENDPOINT, DESCOPE_CLIENT_ID, DESCOPE_CLIENT_SECRET

_cache = {"token": None, "exp": 0}

def get_service_token() -> str:
    if SERVICE_JWT:
        return SERVICE_JWT
    if _cache["token"] and _cache["exp"] - 30 > time.time():
        return _cache["token"]
    if not DESCOPE_TOKEN_ENDPOINT or not DESCOPE_CLIENT_ID or not DESCOPE_CLIENT_SECRET:
        raise RuntimeError("No token provider configured; set SERVICE_JWT or DESCOPE_TOKEN_ENDPOINT+client creds")
    # client credentials post (standard OAuth2)
    data = {
        "grant_type": "client_credentials",
        "client_id": DESCOPE_CLIENT_ID,
        "client_secret": DESCOPE_CLIENT_SECRET,
        "scope": "sniffer:push",
        "audience": "detector-api",
    }
    r = requests.post(DESCOPE_TOKEN_ENDPOINT, data=data, timeout=10)
    r.raise_for_status()
    j = r.json()
    token = j.get("access_token") or j.get("token") or j.get("id_token")
    exp = int(time.time()) + int(j.get("expires_in", 300))
    _cache["token"] = token
    _cache["exp"] = exp
    return token
