"""Disposable integration fixture for JWT-authenticated encrypted uploads.

Creates a temporary SQLite database, ciphertext directory, DPAPI-protected
KEK and fictional user lookup scoped to the current Windows user. The fixture
never reads or writes the real SecureVault database, storage or key material.
Run on Windows with pywin32/DPAPI available.
"""

import os
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import backend.app.api.auth as auth_module

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.security.encrypted_upload_router import (
    create_encrypted_upload_router,
)
from backend.app.security.jwt_encrypted_upload_integration import (
    get_verified_upload_owner,
)
from backend.app.security.key_wrapping import generate_kek
from backend.app.security.tokens import create_access_token
from backend.app.security.windows_kek_store import save_protected_kek


KEY_ID = "test-practice-kek"

FILENAME = "fictional-note.txt"
OTHER_FILENAME = "other-owner-note.txt"

USERS = {
    101: "fictional_alice",
    102: "fictional_bob",
}

DOCUMENTS = {
    1: (101, FILENAME),
    2: (102, OTHER_FILENAME),
}

FICTIONAL_CONTENT = b"Fictional SecureVault integration content."


def _create_disposable_database(db_path):
    """Create only the tables used by the encrypted upload path."""

    with closing(sqlite3.connect(db_path)) as connection:

        connection.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE owned_documents (
                id INTEGER PRIMARY KEY,
                owner_user_id INTEGER NOT NULL,
                filename TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE encrypted_document_keys (
                document_id INTEGER PRIMARY KEY,

                storage_id TEXT NOT NULL UNIQUE
                    CHECK (
                        length(storage_id) = 32
                        AND storage_id
                            NOT GLOB '*[^0-9a-f]*'
                    ),

                key_id TEXT NOT NULL
                    CHECK (
                        length(key_id) BETWEEN 1 AND 64
                        AND key_id
                            NOT GLOB '*[^A-Za-z0-9_-]*'
                    ),

                wrap_nonce BLOB NOT NULL
                    CHECK (
                        typeof(wrap_nonce) = 'blob'
                        AND length(wrap_nonce) = 12
                    ),

                wrapped_dek BLOB NOT NULL
                    CHECK (
                        typeof(wrapped_dek) = 'blob'
                        AND length(wrapped_dek) = 48
                    ),

                created_at TEXT NOT NULL DEFAULT (
                    strftime(
                        '%Y-%m-%dT%H:%M:%SZ',
                        'now'
                    )
                ),

                FOREIGN KEY (document_id)
                    REFERENCES owned_documents(id)
                    ON DELETE CASCADE
            )
            """
        )

        connection.executemany(
            "INSERT INTO users (id, username) VALUES (?, ?)",
            list(USERS.items())
        )

        connection.executemany(
            "INSERT INTO owned_documents "
            "(id, owner_user_id, filename) VALUES (?, ?, ?)",
            [
                (document_id, owner, filename)
                for document_id, (owner, filename)
                in DOCUMENTS.items()
            ]
        )

        connection.commit()


def _fictional_user_lookup(user_id):
    """Return a fictional account without touching the real database."""

    username = USERS.get(user_id)

    if username is None:
        return None

    return {"id": user_id, "username": username}


class TestJWTEncryptedUploadIntegration(unittest.TestCase):
    """Reusable fixture and focused encrypted-upload tests."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        root = Path(self.temp.name)

        self.db_path = root / "vault-test.db"
        self.storage_dir = root / "encrypted"
        self.key_directory = root / "keys"

        self.storage_dir.mkdir()
        self.key_directory.mkdir()

        _create_disposable_database(self.db_path)

        save_protected_kek(
            self.key_directory,
            KEY_ID,
            generate_kek()
        )

        env_patcher = patch.dict(
            os.environ,
            {"SECUREVAULT_JWT_SECRET": secrets.token_urlsafe(48)}
        )
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

        user_patcher = patch.object(
            auth_module,
            "get_user_by_id",
            _fictional_user_lookup
        )
        user_patcher.start()
        self.addCleanup(user_patcher.stop)

        self.app = FastAPI()

        self.app.include_router(
            create_encrypted_upload_router(
                db_path=self.db_path,
                storage_dir=self.storage_dir,
                key_directory=self.key_directory,
                key_id=KEY_ID,
                authenticated_owner_dependency=(
                    get_verified_upload_owner
                )
            )
        )

        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)

        self.content = FICTIONAL_CONTENT

    def token_for(self, user_id):
        """Issue a short-lived JWT for a fictional account."""

        return create_access_token(user_id)

    def upload(
        self,
        token,
        document_id=1,
        filename=FILENAME
    ):
        """Upload fictional content through the authenticated router."""

        return self.client.post(
            f"/documents/{document_id}/encrypted-content",
            params={"filename": filename},
            content=self.content,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/octet-stream"
            }
        )

    def test_owner_upload_stores_ciphertext_only(self):
        response = self.upload(self.token_for(101))

        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()["encrypted"])

        stored = list(self.storage_dir.glob("*.svenc"))
        self.assertEqual(len(stored), 1)
        self.assertNotIn(self.content, stored[0].read_bytes())

    def test_anonymous_upload_rejected(self):
        response = self.client.post(
            "/documents/1/encrypted-content",
            params={"filename": FILENAME},
            content=self.content,
            headers={"Content-Type": "application/octet-stream"}
        )

        self.assertEqual(response.status_code, 401)

    def test_invalid_jwt_rejected(self):
        response = self.upload("invalid.jwt.value")

        self.assertEqual(response.status_code, 401)

    def test_cross_owner_upload_not_found(self):
        response = self.upload(self.token_for(102), document_id=1)

        self.assertEqual(response.status_code, 404)

    def test_wrong_media_type_rejected(self):
        response = self.client.post(
            "/documents/1/encrypted-content",
            params={"filename": FILENAME},
            content=self.content,
            headers={
                "Authorization": f"Bearer {self.token_for(101)}",
                "Content-Type": "text/plain"
            }
        )

        self.assertEqual(response.status_code, 415)

    def test_filename_mismatch_rejected(self):
        response = self.upload(
            self.token_for(101),
            filename="different-name.txt"
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
