"""Migration 004: record the plaintext SHA-256 next to each wrapped DEK.

Adds a nullable ``content_sha256`` column to ``encrypted_document_keys``.

* New uploads always fill it.
* Rows written before this migration keep NULL. They still decrypt (the
  ciphertext format is unchanged); the first successful, GCM-authenticated
  download records the fingerprint so every later download is verified.

The column is added with ``ALTER TABLE ... ADD COLUMN`` which never rewrites
or drops existing rows. ``ensure_content_sha256_column`` is idempotent and is
also called lazily by the repository, so a database that was never migrated
explicitly upgrades itself on its first new upload.
"""

import sqlite3
from contextlib import closing
from pathlib import Path


MIGRATION_VERSION = 4
MIGRATION_NAME = "add_encrypted_document_content_sha256"

COLUMN_DEFINITION = (
    "content_sha256 TEXT CHECK (content_sha256 IS NULL OR "
    "(length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'))"
)


def _table_exists(connection, name):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone() is not None


def has_content_sha256_column(connection):
    return any(
        row[1] == "content_sha256"
        for row in connection.execute("PRAGMA table_info(encrypted_document_keys)")
    )


def ensure_content_sha256_column(connection):
    """Add the column if the key table exists and lacks it. Returns True if added."""

    if not _table_exists(connection, "encrypted_document_keys"):
        return False
    if has_content_sha256_column(connection):
        return False
    connection.execute(f"ALTER TABLE encrypted_document_keys ADD COLUMN {COLUMN_DEFINITION}")
    return True


def apply_migration_004(db_path):
    """Apply and record migration 004 (requires migration 003)."""

    db_path = Path(db_path)
    if not db_path.is_file():
        raise FileNotFoundError("Existing SQLite database not found")

    with closing(sqlite3.connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            if not _table_exists(connection, "schema_migrations"):
                raise RuntimeError("Migration history table is missing")
            versions = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
            if MIGRATION_VERSION in versions:
                if not has_content_sha256_column(connection):
                    raise RuntimeError("Migration 004 is recorded, but its column is missing")
                connection.commit()
                return "ALREADY APPLIED"
            if 3 not in versions:
                raise RuntimeError("Migration 003 must be applied first")
            ensure_content_sha256_column(connection)
            connection.execute(
                "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                (MIGRATION_VERSION, MIGRATION_NAME),
            )
            connection.commit()
            return "MIGRATION APPLIED SUCCESSFULLY"
        except Exception:
            connection.rollback()
            raise
