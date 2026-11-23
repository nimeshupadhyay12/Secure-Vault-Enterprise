
import sqlite3
from pathlib import Path
from contextlib import closing

from backend.app.core import settings


BACKEND_DIR = Path(__file__).resolve().parents[2]

# Single source of truth for the main database location.
# Override with SECUREVAULT_DB_PATH (environment or runtime/securevault.env).
DATABASE_PATH = settings.db_path()


# Tables added for authentication hardening and auditing.
# All statements are idempotent (IF NOT EXISTS).
SECURITY_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        family_id TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        family_expires_at INTEGER NOT NULL,
        used_at INTEGER,
        revoked_at INTEGER,
        revoke_reason TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id)",
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)",
    """
    CREATE TABLE IF NOT EXISTS revoked_access_tokens (
        jti TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS auth_failures (
        username TEXT PRIMARY KEY,
        failure_count INTEGER NOT NULL DEFAULT 0,
        window_start INTEGER NOT NULL,
        locked_until INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        document_id INTEGER,
        outcome TEXT NOT NULL,
        detail TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        mac_alg TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, id)",
)


def apply_security_schema(connection):
    for statement in SECURITY_SCHEMA:
        connection.execute(statement)


def initialize_database(db_path=DATABASE_PATH):
    """Create the base tables used by the application (idempotent)."""

    db_path = Path(db_path)

    db_path.parent.mkdir(parents=True, exist_ok=True)

    # closing() ensures the connection is closed
    with closing(sqlite3.connect(db_path)) as connection:

        with connection:

            connection.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL
                        CHECK(size_bytes >= 0),
                    sha256 TEXT NOT NULL
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                )
            """)

            apply_security_schema(connection)
