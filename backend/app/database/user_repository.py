
import re
import sqlite3
from contextlib import closing

from backend.app.database.db import (
    DATABASE_PATH,
    initialize_database
)

from backend.app.security.passwords import (
    MAX_PASSWORD_LENGTH,
    burn_dummy_verification,
    hash_password,
    needs_rehash,
    password_policy_errors,
    verify_password
)


USERNAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,99}")


def register_user(username, password, db_path=DATABASE_PATH, enforce_policy=True):
    """Register a user and store their Argon2id password hash.

    New passwords must satisfy the password policy (NIST SP 800-63B style:
    minimum length, maximum length, blocklist, not containing the username).
    """

    initialize_database(db_path)

    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username cannot be empty.")

    if USERNAME_PATTERN.fullmatch(username) is None:
        raise ValueError(
            "Username must be 1-100 letters, digits, '.', '_', '@' or '-'."
        )

    if not password:
        raise ValueError("Password cannot be empty.")

    if enforce_policy:
        errors = password_policy_errors(password, username)
        if errors:
            raise ValueError("; ".join(errors))

    # Hash the password before storing it
    hashed_password = hash_password(password)

    with closing(sqlite3.connect(db_path)) as connection:

        try:
            with connection:

                cursor = connection.execute(
                    """
                    INSERT INTO users
                    (username, password_hash)
                    VALUES (?, ?)
                    """,
                    (username, hashed_password)
                )

                return cursor.lastrowid

        except sqlite3.IntegrityError:
            raise ValueError(
                "Username already exists."
            ) from None


def authenticate_user(
    username,
    password,
    db_path=DATABASE_PATH
):
    """Check the saved account password.

    Unknown usernames still pay for one Argon2 verification so that the
    response time does not reveal whether an account exists. Hashes created
    with older Argon2 parameters are upgraded after a successful login.
    """

    initialize_database(db_path)

    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
        return None

    with closing(sqlite3.connect(db_path)) as connection:

        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if row is None:
            burn_dummy_verification(password)
            return None

        if not verify_password(row["password_hash"], password):
            return None

        if needs_rehash(row["password_hash"]):
            with connection:
                connection.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hash_password(password), row["id"])
                )

        return {
            "id": row["id"],
            "username": row["username"]
        }


def get_user_by_id(user_id, db_path=DATABASE_PATH):
    """Retrieve a user without exposing the password hash."""

    initialize_database(db_path)

    with closing(sqlite3.connect(db_path)) as connection:

        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT id, username
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if row is None:
            return None

        return dict(row)
