"""Security helpers used by the hardened application mode."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode


def escape(value: str) -> str:
    return html.escape(value, quote=True)


_EPHEMERAL_DEV_SECRET = secrets.token_bytes(32)


def _secret() -> bytes:
    configured = os.environ.get("APP_SECRET")
    return configured.encode() if configured else _EPHEMERAL_DEV_SECRET


def sign_session(username: str, ttl_seconds: int = 3600) -> str:
    payload = {
        "username": username,
        "exp": int(time.time()) + ttl_seconds,
        "nonce": secrets.token_hex(8),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = urlsafe_b64encode(raw).decode().rstrip("=")
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_session(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    expected = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(urlsafe_b64decode(padded).decode())
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    username = payload.get("username")
    return username if isinstance(username, str) else None


def csrf_token(session_token: str) -> str:
    return hmac.new(_secret(), ("csrf:" + session_token).encode(), hashlib.sha256).hexdigest()


def valid_csrf(session_token: str | None, supplied: str | None) -> bool:
    if not session_token or not supplied:
        return False
    return hmac.compare_digest(csrf_token(session_token), supplied)
