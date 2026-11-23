"""Short-lived JWT access tokens.

* HS256 only. ``jwt.decode`` is called with ``algorithms=[HS256]`` so
  ``alg: none`` and algorithm-confusion tokens are rejected.
* Claims: sub, iss, aud, iat, nbf, exp, jti, typ. All are required on decode.
* ``typ`` must be ``access`` so a token minted for another purpose can never
  be replayed as an access token.
* ``jti`` is a random identifier that lets logout revoke one access token
  server-side before it expires.
* Lifetime: 15 minutes.
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt

from backend.app.core import settings


ALGORITHM = "HS256"
ISSUER = "securevault-local"
AUDIENCE = "securevault-api"
TOKEN_TYPE = "access"
TOKEN_LIFETIME_MINUTES = 15
TOKEN_LIFETIME_SECONDS = TOKEN_LIFETIME_MINUTES * 60
MIN_SECRET_LENGTH = 32

REQUIRED_CLAIMS = ["sub", "iss", "aud", "iat", "nbf", "exp", "jti", "typ"]


# Placeholder values that appear in documentation or examples. They are
# public, so a server must never sign tokens with them outside dev mode.
PLACEHOLDER_MARKERS = ("change-me", "changeme", "replace-me", "example", "placeholder")

# Development mode only: a random per-process secret, never a fixed default.
_dev_secret = None


def _looks_like_placeholder(secret):
    lowered = secret.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS) or len(set(secret)) < 8


def get_token_secret():
    """Return the HS256 signing key.

    * Must be at least 32 characters.
    * Documented/placeholder values and low-variety strings are refused
      unless ``SECUREVAULT_ENV=development``.
    * In development mode, when no secret is configured, a random secret is
      generated for this process only (tokens die on restart). There is no
      hard-coded default secret anywhere in the code base.
    """

    global _dev_secret

    secret = settings.get("SECUREVAULT_JWT_SECRET", "") or ""
    development = settings.is_development()

    if not secret and development:
        if _dev_secret is None:
            _dev_secret = secrets.token_urlsafe(48)
        return _dev_secret

    if len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            "SECUREVAULT_JWT_SECRET must contain "
            "at least 32 characters."
        )

    if not development and _looks_like_placeholder(secret):
        raise RuntimeError(
            "SECUREVAULT_JWT_SECRET looks like a placeholder; "
            "generate a random secret (python -m backend.manage setup)."
        )

    return secret


def create_access_token(user_id, lifetime_seconds=TOKEN_LIFETIME_SECONDS):
    """Create a signed, expiring JWT."""

    if type(user_id) is not int or user_id < 1:
        raise ValueError("Invalid user ID")

    if not 1 <= lifetime_seconds <= TOKEN_LIFETIME_SECONDS:
        raise ValueError("Access tokens may live at most 15 minutes")

    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=lifetime_seconds),
        "jti": uuid.uuid4().hex,
        "typ": TOKEN_TYPE,
    }

    return jwt.encode(
        payload,
        get_token_secret(),
        algorithm=ALGORITHM
    )


def decode_access_claims(token):
    """Verify a JWT and return its validated claims."""

    payload = jwt.decode(
        token,
        get_token_secret(),
        algorithms=[ALGORITHM],
        issuer=ISSUER,
        audience=AUDIENCE,
        options={"require": REQUIRED_CLAIMS}
    )

    if payload.get("typ") != TOKEN_TYPE:
        raise jwt.InvalidTokenError("Wrong token type")

    jti = payload.get("jti")
    if not isinstance(jti, str) or not 16 <= len(jti) <= 64:
        raise jwt.InvalidTokenError("Invalid token identifier")

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub.isdigit():
        raise ValueError("Invalid user ID")

    user_id = int(sub)

    if user_id < 1:
        raise ValueError("Invalid user ID")

    payload["user_id"] = user_id
    return payload


def decode_access_token(token):
    """Verify a JWT and return its user ID."""

    return decode_access_claims(token)["user_id"]
