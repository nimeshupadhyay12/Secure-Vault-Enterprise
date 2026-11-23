"""Server-side session state: login lockout, refresh tokens, revocation.

Refresh tokens
--------------
* Opaque 256-bit random strings (``secrets.token_urlsafe(32)``). Only their
  SHA-256 hash is stored, so a database leak does not leak usable tokens.
  (A fast hash is fine here: the input has 256 bits of entropy.)
* Rotation: every successful ``/auth/refresh`` marks the presented token as
  used and issues a new one in the same *family*.
* Reuse detection: presenting a token that was already used or revoked means
  it was copied by someone else. The whole family is revoked, which logs out
  both the attacker and the victim (RFC 6749 security BCP / OAuth 2.1).
* Idle timeout 2 hours per token, absolute family lifetime 12 hours.

Access-token revocation
-----------------------
Logout stores the access token's ``jti`` until its ``exp``; the auth
dependency rejects revoked ``jti`` values.

Login lockout
-------------
Failures are counted per username (whether or not the account exists, so
the lockout itself does not reveal which usernames are registered). After
``SECUREVAULT_LOGIN_MAX_FAILURES`` failures inside the window the username is
locked for ``SECUREVAULT_LOGIN_LOCKOUT_SECONDS``. While locked, the password
is not even checked.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path

from backend.app.core import settings
from backend.app.database import db as db_module
from backend.app.database.db import apply_security_schema


REFRESH_IDLE_SECONDS = 2 * 60 * 60
REFRESH_ABSOLUTE_SECONDS = 12 * 60 * 60


class RefreshTokenError(Exception):
    """Refresh token invalid, expired or revoked."""


class RefreshTokenReuse(RefreshTokenError):
    """A rotated/revoked refresh token was presented again."""

    def __init__(self, user_id, family_id):
        super().__init__("Refresh token reuse detected")
        self.user_id = user_id
        self.family_id = family_id


def _db(db_path=None) -> Path:
    return Path(db_path) if db_path else Path(db_module.DATABASE_PATH)


def _connect(db_path=None):
    path = _db(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    apply_security_schema(connection)
    connection.commit()
    return connection


def _now() -> int:
    return int(time.time())


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- lockout

def lockout_policy():
    return {
        "max_failures": settings.get_int("SECUREVAULT_LOGIN_MAX_FAILURES", 5, minimum=1),
        "window": settings.get_int("SECUREVAULT_LOGIN_WINDOW_SECONDS", 900, minimum=1),
        "lockout": settings.get_int("SECUREVAULT_LOGIN_LOCKOUT_SECONDS", 900, minimum=1),
    }


def seconds_until_unlocked(username, db_path=None) -> int:
    """0 when the username may attempt a login, else seconds remaining."""

    with closing(_connect(db_path)) as connection:
        row = connection.execute(
            "SELECT locked_until FROM auth_failures WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None:
        return 0
    return max(0, int(row["locked_until"]) - _now())


def register_login_failure(username, db_path=None) -> bool:
    """Count one failure. Returns True when this failure triggered a lock."""

    policy = lockout_policy()
    now = _now()
    with closing(_connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT failure_count, window_start, locked_until FROM auth_failures WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None or now - int(row["window_start"]) > policy["window"]:
            count, window_start = 1, now
        else:
            count, window_start = int(row["failure_count"]) + 1, int(row["window_start"])
        locked_until = 0
        triggered = False
        if count >= policy["max_failures"]:
            locked_until = now + policy["lockout"]
            triggered = True
            count, window_start = 0, now
        connection.execute(
            """INSERT INTO auth_failures (username, failure_count, window_start, locked_until)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET failure_count = excluded.failure_count,
                   window_start = excluded.window_start, locked_until = excluded.locked_until""",
            (username, count, window_start, locked_until),
        )
        connection.commit()
    return triggered


def clear_login_failures(username, db_path=None):
    with closing(_connect(db_path)) as connection, connection:
        connection.execute("DELETE FROM auth_failures WHERE username = ?", (username,))


# ---------------------------------------------------------- refresh tokens

def issue_refresh_token(user_id, db_path=None, family_id=None, family_expires_at=None,
                        connection=None):
    """Create a refresh token. Returns (token, expires_in_seconds)."""

    now = _now()
    family_id = family_id or uuid.uuid4().hex
    family_expires_at = family_expires_at or now + REFRESH_ABSOLUTE_SECONDS
    expires_at = min(now + REFRESH_IDLE_SECONDS, family_expires_at)
    token = secrets.token_urlsafe(32)

    def _insert(conn):
        conn.execute(
            """INSERT INTO refresh_tokens (user_id, family_id, token_hash, issued_at,
                   expires_at, family_expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, family_id, hash_refresh_token(token), now, expires_at, family_expires_at),
        )

    if connection is not None:
        _insert(connection)
    else:
        with closing(_connect(db_path)) as conn, conn:
            _insert(conn)
    return token, expires_at - now


def rotate_refresh_token(token, db_path=None):
    """Consume ``token`` and return (user_id, new_token, expires_in).

    Raises RefreshTokenReuse (family revoked) or RefreshTokenError.
    """

    if not isinstance(token, str) or not 20 <= len(token) <= 200:
        raise RefreshTokenError("Invalid refresh token")

    now = _now()
    token_hash = hash_refresh_token(token)
    with closing(_connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                "SELECT * FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                raise RefreshTokenError("Unknown refresh token")

            if row["used_at"] is not None or row["revoked_at"] is not None:
                connection.execute(
                    """UPDATE refresh_tokens SET revoked_at = ?, revoke_reason = 'reuse_detected'
                       WHERE family_id = ? AND revoked_at IS NULL""",
                    (now, row["family_id"]),
                )
                connection.commit()
                raise RefreshTokenReuse(row["user_id"], row["family_id"])

            if now >= int(row["expires_at"]) or now >= int(row["family_expires_at"]):
                connection.execute(
                    "UPDATE refresh_tokens SET revoked_at = ?, revoke_reason = 'expired' WHERE id = ?",
                    (now, row["id"]),
                )
                connection.commit()
                raise RefreshTokenError("Refresh token expired")

            connection.execute(
                "UPDATE refresh_tokens SET used_at = ? WHERE id = ?", (now, row["id"])
            )
            new_token, expires_in = issue_refresh_token(
                row["user_id"],
                family_id=row["family_id"],
                family_expires_at=int(row["family_expires_at"]),
                connection=connection,
            )
            connection.commit()
            return int(row["user_id"]), new_token, expires_in
        except RefreshTokenError:
            raise
        except Exception:
            connection.rollback()
            raise


def revoke_refresh_family_for_token(token, user_id, db_path=None) -> bool:
    """Revoke the family of ``token`` if it belongs to ``user_id``."""

    if not isinstance(token, str) or not token:
        return False
    with closing(_connect(db_path)) as connection, connection:
        row = connection.execute(
            "SELECT family_id, user_id FROM refresh_tokens WHERE token_hash = ?",
            (hash_refresh_token(token),),
        ).fetchone()
        if row is None or int(row["user_id"]) != int(user_id):
            return False
        connection.execute(
            """UPDATE refresh_tokens SET revoked_at = ?, revoke_reason = 'logout'
               WHERE family_id = ? AND revoked_at IS NULL""",
            (_now(), row["family_id"]),
        )
    return True


def revoke_all_refresh_tokens(user_id, db_path=None) -> int:
    with closing(_connect(db_path)) as connection, connection:
        cursor = connection.execute(
            """UPDATE refresh_tokens SET revoked_at = ?, revoke_reason = 'logout_all'
               WHERE user_id = ? AND revoked_at IS NULL""",
            (_now(), user_id),
        )
        return cursor.rowcount


# ------------------------------------------------- access-token revocation

def revoke_access_token(jti, user_id, expires_at, db_path=None):
    with closing(_connect(db_path)) as connection, connection:
        connection.execute(
            "INSERT OR IGNORE INTO revoked_access_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)",
            (jti, user_id, int(expires_at)),
        )
        # Housekeeping: expired entries can never be presented again.
        connection.execute("DELETE FROM revoked_access_tokens WHERE expires_at < ?", (_now(),))


def is_access_token_revoked(jti, db_path=None) -> bool:
    with closing(_connect(db_path)) as connection:
        row = connection.execute(
            "SELECT 1 FROM revoked_access_tokens WHERE jti = ?", (jti,)
        ).fetchone()
    return row is not None
