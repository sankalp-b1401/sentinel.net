# detector/auth/jwk_verify.py
"""
JWKS fetch + JWT verification for Descope tokens (remote-only).
This implementation uses `requests` to fetch the JWKS and PyJWT to construct
the RSA public key and decode tokens.

Behavior:
 - Fetch remote JWKS with a few retries.
 - Select the key matching the token's 'kid' header.
 - Build a public key via PyJWT's RSAAlgorithm and decode the token.
 - Verify 'aud' (SERVICE_AUDIENCE) and optionally check requested scope.

Raises Exception (with helpful message) on any failure so server can return 401.
"""
from __future__ import annotations
import json
import time
import logging
from typing import Dict, Optional
from pathlib import Path

import requests
from jwt import decode
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError

from config import DESCOPE_JWKS_URL, SERVICE_AUDIENCE

log = logging.getLogger("auth.jwk_verify")
JWKS_FETCH_TIMEOUT = 8.0
JWKS_FETCH_HEADERS = {
    "User-Agent": "sentinel.net-detector/1.0",
    "Accept": "application/json",
}

def _get_kid_from_token(token: str) -> Optional[str]:
    try:
        import base64, json as _json
        hdr_b64 = token.split(".")[0]
        hdr_b64 += "=" * ((4 - len(hdr_b64) % 4) % 4)
        hdr = _json.loads(base64.urlsafe_b64decode(hdr_b64).decode())
        return hdr.get("kid")
    except Exception:
        return None

def _fetch_jwks(url: str, retries: int = 3, delay: float = 0.5) -> Dict:
    if not url:
        raise RuntimeError("DESCOPE_JWKS_URL not configured")
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            log.debug("JWKS fetch attempt %d -> %s", attempt, url)
            r = requests.get(url, headers=JWKS_FETCH_HEADERS, timeout=JWKS_FETCH_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            last_exc = e
            log.warning("JWKS fetch attempt %d failed: %s", attempt, repr(e))
            if attempt < retries:
                time.sleep(delay)
    # final failure
    raise Exception(f"Failed to fetch JWKS from {url}: {repr(last_exc)}")

def _find_key_for_kid(jwks: Dict, kid: str) -> Optional[Dict]:
    if not jwks:
        return None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k
    return None

def verify_token_and_scope(token: str, required_scope: Optional[str] = None) -> Dict:
    """
    Verify the JWT. Returns decoded claims dict on success.
    Raises Exception on error (caller should return 401).
    """
    if not token:
        raise Exception("no token provided")

    kid = _get_kid_from_token(token)
    if not kid:
        raise Exception("token missing 'kid' header")

    # fetch JWKS (remote-only)
    jwks = _fetch_jwks(DESCOPE_JWKS_URL, retries=3, delay=0.5)

    keyobj = _find_key_for_kid(jwks, kid)
    if keyobj is None:
        raise Exception(f"No JWKS key found for kid={kid}")

    try:
        pub = RSAAlgorithm.from_jwk(json.dumps(keyobj))
        claims = decode(token, pub, algorithms=["RS256"], audience=SERVICE_AUDIENCE)
    except ExpiredSignatureError as e:
        raise Exception("token expired")
    except InvalidSignatureError as e:
        raise Exception("invalid token signature")
    except Exception as e:
        raise Exception(f"token decode error: {e}")

    # scope check (if requested)
    if required_scope:
        sc = claims.get("scope", "")
        if isinstance(sc, str):
            ok = required_scope in sc.split()
        elif isinstance(sc, list):
            ok = required_scope in sc
        else:
            ok = False
        if not ok:
            raise Exception("missing required scope")

    return claims
