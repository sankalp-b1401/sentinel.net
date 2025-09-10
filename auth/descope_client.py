# auth/descope_client.py
"""
Helper to obtain a service token for calling detector HTTP API.

Usage notes:
- In development you can set SERVICE_JWT env var and this function will return it (static dev token).
- In production you generally configure DESCOPE_TOKEN_ENDPOINT + DESCOPE_CLIENT_ID + DESCOPE_CLIENT_SECRET
  and the helper will perform an OAuth2 client_credentials POST to mint a short-lived token.
- A tiny in-memory cache is maintained to avoid frequent token requests.
"""

import time
import requests
from config import SERVICE_JWT, DESCOPE_TOKEN_ENDPOINT, DESCOPE_CLIENT_ID, DESCOPE_CLIENT_SECRET

# Simple in-memory cache storing token and expiry time
_cache = {"token": None, "exp": 0}

def get_service_token() -> str:
    """
    Return a Bearer token string for authenticating requests.

    Behavior:
    - If SERVICE_JWT env var set, returns it immediately (developer convenience).
    - Else if a cached token exists and is not near expiry, return cached token.
    - Otherwise perform a client_credentials POST to DESCOPE_TOKEN_ENDPOINT to fetch a token.
      Expects response JSON with access_token (or token/id_token) and expires_in seconds.
    - Raises RuntimeError if no method available to obtain a token.
    """
    # Developer override: use static token if provided
    if SERVICE_JWT:
        return SERVICE_JWT

    # Return cached token if valid (with a small safety margin)
    if _cache["token"] and _cache["exp"] - 30 > time.time():
        return _cache["token"]

    # Ensure token provider is configured
    if not DESCOPE_TOKEN_ENDPOINT or not DESCOPE_CLIENT_ID or not DESCOPE_CLIENT_SECRET:
        raise RuntimeError("No token provider configured; set SERVICE_JWT or DESCOPE_TOKEN_ENDPOINT+client creds")

    # Standard OAuth2 client_credentials request body
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
    # Some providers return access_token, others use token or id_token — handle common keys
    token = j.get("access_token") or j.get("token") or j.get("id_token")
    exp = int(time.time()) + int(j.get("expires_in", 300))
    _cache["token"] = token
    _cache["exp"] = exp
    return token
