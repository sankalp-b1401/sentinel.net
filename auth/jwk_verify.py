# auth/jwk_verify.py
"""
JWKS fetch + JWT verification helpers.

Responsibilities:
- Fetch JWKS from configured DESCOPE_JWKS_URL.
- Find the key matching JWT 'kid' and verify the token using RSA public key.
- Provide convenience functions:
  - verify_token_and_scope(token, required_scope=None): verifies signature, expiry, audience and optionally scope.
  - validate_jwks_and_audience(jwks_url, audience, sample_token=None): validate JWKS endpoint reachable and optionally test a sample token.

Technologies:
- requests: to fetch remote JWKS JSON.
- PyJWT (jwt.decode) for JWT parsing and verification.
- RSAAlgorithm.from_jwk to convert JWK to public RSA key for verification.
"""

from __future__ import annotations
import json
import time
import logging
from typing import Dict, Optional, Tuple
from pathlib import Path
from email.utils import parsedate_to_datetime
import datetime

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
    """
    Extract the 'kid' value from the JWT header without validating signature.
    This uses base64 URL decoding of the header segment.
    """
    try:
        import base64, json as _json
        hdr_b64 = token.split(".")[0]
        hdr_b64 += "=" * ((4 - len(hdr_b64) % 4) % 4)
        hdr = _json.loads(base64.urlsafe_b64decode(hdr_b64).decode())
        return hdr.get("kid")
    except Exception:
        return None

def _fetch_jwks(url: str, retries: int = 3, delay: float = 0.5) -> Dict:
    """
    Fetch JWKS JSON from url with small retry/backoff.
    Raises on failure so callers can treat it as a hard failure (server misconfig).
    """
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
    raise Exception(f"Failed to fetch JWKS from {url}: {repr(last_exc)}")

def _fetch_jwks_with_meta(url: str, retries: int = 3, delay: float = 0.5) -> Tuple[Dict, Optional[str]]:
    """
    Fetch JWKS and return tuple (jwks_json, server_date_header_or_None).
    We use the Date header to estimate server time for clock skew checks.
    """
    if not url:
        raise RuntimeError("DESCOPE_JWKS_URL not configured")
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            log.debug("JWKS fetch-with-meta attempt %d -> %s", attempt, url)
            r = requests.get(url, headers=JWKS_FETCH_HEADERS, timeout=JWKS_FETCH_TIMEOUT)
            r.raise_for_status()
            server_date = r.headers.get("Date")
            return r.json(), server_date
        except Exception as e:
            last_exc = e
            log.warning("JWKS fetch-with-meta attempt %d failed: %s", attempt, repr(e))
            if attempt < retries:
                time.sleep(delay)
    raise Exception(f"Failed to fetch JWKS from {url}: {repr(last_exc)}")

def _find_key_for_kid(jwks: Dict, kid: str) -> Optional[Dict]:
    """Locate a JWK matching the provided 'kid' value inside a JWKS dict."""
    if not jwks:
        return None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k
    return None

def verify_token_and_scope(token: str, required_scope: Optional[str] = None) -> Dict:
    """
    Verify the JWT and optionally the presence of a required scope.

    - Fetch JWKS.
    - Find the matching key by kid.
    - Convert JWK -> public key and decode JWT with audience check.
    - Raises Exception on any verification failure (caller should handle and return 401).
    - Returns decoded claims dict on success.
    """
    if not token:
        raise Exception("no token provided")

    kid = _get_kid_from_token(token)
    if not kid:
        raise Exception("token missing 'kid' header")

    jwks = _fetch_jwks(DESCOPE_JWKS_URL, retries=3, delay=0.5)
    keyobj = _find_key_for_kid(jwks, kid)
    if keyobj is None:
        raise Exception(f"No JWKS key found for kid={kid}")

    try:
        pub = RSAAlgorithm.from_jwk(json.dumps(keyobj))
        claims = decode(token, pub, algorithms=["RS256"], audience=SERVICE_AUDIENCE)
    except ExpiredSignatureError:
        raise Exception("token expired")
    except InvalidSignatureError:
        raise Exception("invalid token signature")
    except Exception as e:
        raise Exception(f"token decode error: {e}")

    # scope check if requested
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

# ---- Additional helpers for config validation ----

def _decode_token_with_audience(token: str, audience: str) -> Dict:
    """
    Decode token using the JWKS and the provided audience. Useful for testing sample tokens.
    Raises on failures similar to verify_token_and_scope.
    """
    if not token:
        raise Exception("no token provided for decode")
    kid = _get_kid_from_token(token)
    if not kid:
        raise Exception("token missing 'kid' header for decode")
    jwks = _fetch_jwks(DESCOPE_JWKS_URL, retries=3, delay=0.5)
    keyobj = _find_key_for_kid(jwks, kid)
    if keyobj is None:
        raise Exception(f"No JWKS key found for kid={kid}")
    try:
        pub = RSAAlgorithm.from_jwk(json.dumps(keyobj))
        claims = decode(token, pub, algorithms=["RS256"], audience=audience)
        return claims
    except ExpiredSignatureError:
        raise Exception("token expired during validation")
    except InvalidSignatureError:
        raise Exception("invalid token signature during validation")
    except Exception as e:
        raise Exception(f"token decode error during validation: {e}")

def validate_jwks_and_audience(jwks_url: str, audience: str, sample_token: Optional[str] = None,
                               max_skew_seconds: int = 30) -> Dict:
    """
    Validate JWKS endpoint reachability and local/server clock skew.

    Steps:
    - Fetch JWKS and the Date header to estimate server time.
    - Compute clock skew (server_time - local_time) and include it in returned info.
    - Optionally try to decode a sample_token against the given audience to validate audience config.
    - Returns a dict with keys: key_count, server_date, local_date, skew_seconds, sample_token_claims (if sample_token provided)
    """
    jwks, server_date = _fetch_jwks_with_meta(jwks_url)
    key_count = len(jwks.get("keys", []))
    server_dt = None
    skew = None
    if server_date:
        try:
            server_dt = parsedate_to_datetime(server_date).astimezone(datetime.timezone.utc)
            local_dt = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
            skew = (server_dt - local_dt).total_seconds()
        except Exception:
            server_dt = None
            skew = None

    info = {
        "key_count": key_count,
        "server_date": server_dt.isoformat() if server_dt is not None else None,
        "local_date": datetime.datetime.utcnow().isoformat() + "Z",
        "skew_seconds": skew,
    }

    if sample_token:
        # Try decoding sample token with provided audience to confirm audience configuration
        try:
            claims = _decode_token_with_audience(sample_token, audience)
            info["sample_token_claims"] = claims
        except Exception as e:
            info["sample_token_error"] = str(e)

    # Check skew threshold and raise if skew too large
    if skew is not None and abs(skew) > max_skew_seconds:
        raise Exception(f"Clock skew too large between JWKS server and local machine: {skew} seconds")

    return info
