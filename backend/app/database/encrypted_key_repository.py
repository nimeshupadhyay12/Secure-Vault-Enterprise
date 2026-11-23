
import sqlite3

from contextlib import closing
from pathlib import Path

from backend.app.database.db import DATABASE_PATH

from backend.app.security.encrypted_storage import (
    validate_storage_id
)

from backend.app.security.kek_config import (
    validate_kek_id
)

from backend.app.security.integrity import validate_sha256_hex

from backend.app.database.migrations.migration_004 import (
    ensure_content_sha256_column,
    has_content_sha256_column
)


def validate_positive_id(value, name):
    """Require a positive integer ID."""

    if type(value) is not int or value < 1:
        raise ValueError(
            f"{name} must be a positive integer"
        )


def check_existing_database(db_path):
    """Never silently create a new SQLite database."""

    path = Path(db_path)

    if not path.is_file():
        raise FileNotFoundError(
            "Existing SQLite database not found"
        )

    return path


def save_encrypted_key_record(
    document_id,
    owner_user_id,
    storage_id,
    key_id,
    wrap_nonce,
    wrapped_dek,
    db_path=DATABASE_PATH,
    content_sha256=None
):
    """
    Save encrypted-key metadata for an owned document.

    ``content_sha256`` is the plaintext fingerprint verified on every
    download. Never stores a raw DEK or KEK.
    Never creates an owned document.
    """

    if content_sha256 is not None:
        validate_sha256_hex(content_sha256)

    validate_positive_id(
        document_id, "Document ID"
    )

    validate_positive_id(
        owner_user_id, "Owner user ID"
    )

    validate_storage_id(storage_id)
    validate_kek_id(key_id)

    if (
        not isinstance(wrap_nonce, bytes)
        or len(wrap_nonce) != 12
    ):
        raise ValueError(
            "Wrapping nonce must be 12 bytes"
        )

    if (
        not isinstance(wrapped_dek, bytes)
        or len(wrapped_dek) != 48
    ):
        raise ValueError(
            "Wrapped DEK must be 48 bytes"
        )

    path = check_existing_database(db_path)

    with closing(sqlite3.connect(path)) as connection:

        connection.execute("PRAGMA foreign_keys = ON")

        with connection:

            # Migration 004 (idempotent): make sure the
            # fingerprint column exists before writing.
            ensure_content_sha256_column(connection)

            # Insert only when the document belongs
            # to the specified owner.
            cursor = connection.execute(
                """
                INSERT INTO encrypted_document_keys (
                    document_id,
                    storage_id,
                    key_id,
                    wrap_nonce,
                    wrapped_dek,
                    content_sha256
                )
                SELECT
                    d.id, ?, ?, ?, ?, ?
                FROM owned_documents AS d
                WHERE d.id = ?
                  AND d.owner_user_id = ?
                """,
                (
                    storage_id,
                    key_id,
                    wrap_nonce,
                    wrapped_dek,
                    content_sha256,
                    document_id,
                    owner_user_id
                )
            )

            if cursor.rowcount != 1:
                raise LookupError(
                    "Owned document not found"
                )

    return document_id


def get_encrypted_key_record(
    document_id,
    owner_user_id,
    db_path=DATABASE_PATH
):
    """
    Retrieve encrypted-key metadata for one owner.

    Returns None when the document is not owned
    by the specified user, or has no key record.
    """

    validate_positive_id(
        document_id, "Document ID"
    )

    validate_positive_id(
        owner_user_id, "Owner user ID"
    )

    path = check_existing_database(db_path)

    with closing(sqlite3.connect(path)) as connection:

        connection.row_factory = sqlite3.Row

        # Rows from before migration 004 have no fingerprint column.
        fingerprint = (
            "k.content_sha256"
            if has_content_sha256_column(connection)
            else "NULL"
        )

        row = connection.execute(
            f"""
            SELECT
                k.document_id,
                k.storage_id,
                k.key_id,
                k.wrap_nonce,
                k.wrapped_dek,
                k.created_at,
                {fingerprint} AS content_sha256
            FROM encrypted_document_keys AS k
            JOIN owned_documents AS d
              ON d.id = k.document_id
            WHERE d.id = ?
              AND d.owner_user_id = ?
            """,
            (document_id, owner_user_id)
        ).fetchone()

        if row is None:
            return None

        return dict(row)


def record_content_sha256(
    document_id,
    owner_user_id,
    content_sha256,
    db_path=DATABASE_PATH
):
    """
    Store the fingerprint for a pre-migration row (only if still NULL).

    Called after a GCM-authenticated decryption of a legacy document,
    so later downloads are verified against it.
    """

    validate_positive_id(document_id, "Document ID")
    validate_positive_id(owner_user_id, "Owner user ID")
    validate_sha256_hex(content_sha256)

    path = check_existing_database(db_path)

    with closing(sqlite3.connect(path)) as connection:
        with connection:
            ensure_content_sha256_column(connection)
            cursor = connection.execute(
                """
                UPDATE encrypted_document_keys
                SET content_sha256 = ?
                WHERE document_id = ?
                  AND content_sha256 IS NULL
                  AND document_id IN (
                      SELECT id FROM owned_documents
                      WHERE id = ? AND owner_user_id = ?
                  )
                """,
                (content_sha256, document_id, document_id, owner_user_id)
            )
            return cursor.rowcount == 1
