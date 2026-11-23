"""Authentication routes and the shared ``get_current_user`` dependency.

Flow:
  POST /auth/token    username+password -> 15-min access JWT + refresh token
  POST /auth/refresh  refresh token -> new access JWT + rotated refresh token
  POST /auth/logout   revoke this access token (+ refresh family / all sessions)
  GET  /auth/me       identity of the bearer
  POST /auth/login    deprecated alias of /auth/token (same code path)
"""

import jwt

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)
from pydantic import BaseModel, Field

from backend.app.database.user_repository import (
    authenticate_user,
    get_user_by_id
)
from backend.app.security import audit_log, sessions
from backend.app.security.passwords import MAX_PASSWORD_LENGTH
from backend.app.security.tokens import (
    TOKEN_LIFETIME_SECONDS,
    create_access_token,
    decode_access_claims,
    get_token_secret
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=200)


class LogoutRequest(BaseModel):
    refresh_token: str | None = Field(default=None, max_length=200)
    all_sessions: bool = False


# Reads "Authorization: Bearer <token>"
bearer_scheme = HTTPBearer(auto_error=False)

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _unauthorized(detail):
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"}
    )


def _require_token_service():
    try:
        get_token_secret()
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Token service is not configured"
        ) from None


def _client(request: Request):
    return request.client.host if request.client else None


def _token_pair(user_id, refresh_token, refresh_expires_in):
    return JSONResponse(
        {
            "access_token": create_access_token(user_id),
            "token_type": "bearer",
            "expires_in": TOKEN_LIFETIME_SECONDS,
            "refresh_token": refresh_token,
            "refresh_expires_in": refresh_expires_in,
        },
        headers=NO_STORE,
    )


def _login(request: LoginRequest, http_request: Request):
    """Shared credential check used by /auth/token and /auth/login."""

    _require_token_service()
    username = request.username
    client = _client(http_request)

    retry_after = sessions.seconds_until_unlocked(username)
    if retry_after > 0:
        audit_log.record_event(
            "login_locked", outcome="denied",
            detail={"username": username, "client": client},
        )
        raise HTTPException(
            status_code=429,
            detail="Too many failed sign-in attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = authenticate_user(username, request.password)

    if user is None:
        locked = sessions.register_login_failure(username)
        audit_log.record_event(
            "login_failure", outcome="failure",
            detail={"username": username, "client": client, "locked": locked},
        )
        raise _unauthorized("Invalid username or password")

    sessions.clear_login_failures(username)
    refresh_token, refresh_expires_in = sessions.issue_refresh_token(user["id"])
    audit_log.record_event(
        "login_success", user_id=user["id"], detail={"client": client}
    )
    return _token_pair(user["id"], refresh_token, refresh_expires_in)


@router.post("/token")
def issue_token(request: LoginRequest, http_request: Request):
    """Verify credentials and issue a short-lived access token + refresh token."""

    return _login(request, http_request)


@router.post("/login", deprecated=True)
def login(request: LoginRequest, http_request: Request):
    """Deprecated alias for /auth/token kept for old clients.

    It runs exactly the same lockout, timing-equalised check and audit trail.
    """

    return _login(request, http_request)


@router.post("/refresh")
def refresh(request: RefreshRequest, http_request: Request):
    """Rotate a refresh token. Reusing an old token revokes the whole family."""

    _require_token_service()
    try:
        user_id, new_token, expires_in = sessions.rotate_refresh_token(request.refresh_token)
    except sessions.RefreshTokenReuse as reuse:
        audit_log.record_event(
            "refresh_token_reuse", user_id=reuse.user_id, outcome="denied",
            detail={"family": reuse.family_id[:12], "client": _client(http_request)},
        )
        raise _unauthorized("Invalid refresh token") from None
    except sessions.RefreshTokenError:
        audit_log.record_event(
            "refresh_rejected", outcome="denied",
            detail={"client": _client(http_request)},
        )
        raise _unauthorized("Invalid refresh token") from None

    if get_user_by_id(user_id) is None:
        sessions.revoke_all_refresh_tokens(user_id)
        raise _unauthorized("Invalid refresh token")

    audit_log.record_event("token_refreshed", user_id=user_id)
    return _token_pair(user_id, new_token, expires_in)


def _authenticate_bearer(credentials):
    if credentials is None:
        raise _unauthorized("Authentication required")

    try:
        claims = decode_access_claims(credentials.credentials)

    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Token service is not configured"
        ) from None

    except (jwt.InvalidTokenError, ValueError, OverflowError, TypeError):
        raise _unauthorized("Invalid or expired token") from None

    try:
        revoked = sessions.is_access_token_revoked(claims["jti"])
    except Exception:
        # Fail closed if revocation state cannot be read.
        raise HTTPException(status_code=503, detail="Session service unavailable") from None

    if revoked:
        raise _unauthorized("Invalid or expired token")

    user = get_user_by_id(claims["user_id"])

    if user is None:
        raise _unauthorized("User account not found")

    return user, claims


@router.get("/me")
def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    )
):
    """Return the identity from a valid Bearer token.

    Also used as the authentication dependency by every protected router.
    """

    user, _claims = _authenticate_bearer(credentials)

    return {
        "message": "PROTECTED ROUTE ACCESS GRANTED",
        "user_id": user["id"],
        "username": user["username"]
    }


@router.post("/logout")
def logout(
    request: LogoutRequest | None = None,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    """Revoke the presented access token, and optionally refresh sessions."""

    user, claims = _authenticate_bearer(credentials)
    request = request or LogoutRequest()

    sessions.revoke_access_token(claims["jti"], user["id"], claims["exp"])

    revoked_refresh = 0
    if request.all_sessions:
        revoked_refresh = sessions.revoke_all_refresh_tokens(user["id"])
    elif request.refresh_token:
        revoked_refresh = int(
            sessions.revoke_refresh_family_for_token(request.refresh_token, user["id"])
        )

    audit_log.record_event(
        "logout", user_id=user["id"],
        detail={"all_sessions": request.all_sessions},
    )
    return JSONResponse(
        {"logged_out": True, "refresh_sessions_revoked": revoked_refresh},
        headers=NO_STORE,
    )
