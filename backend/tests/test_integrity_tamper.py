"""Tamper tests: every download path must refuse modified data.

Text/encrypted-content path: reuses the disposable upload fixture.
Binary path: temporary binary DB + ciphertext directory + protected KEK.
"""

import hashlib
import os
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import test_jwt_encrypted_upload_integration as fixture_module

from backend.app.api import vault_binary
from backend.app.database.migrations.migration_004 import has_content_sha256_column
from backend.app.security.encrypted_download_router import create_jwt_encrypted_download_router
from backend.app.security.integrity import IntegrityVerificationError, verify_sha256
from backend.app.security.key_wrapping import generate_kek
from backend.app.security.tokens import create_access_token
from backend.app.security.windows_kek_store import save_protected_kek


class TestVerifySha256(unittest.TestCase):
    def test_constant_time_helper(self):
        data = b"fingerprint me"
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(verify_sha256(data, digest), digest)
        self.assertEqual(verify_sha256(data, digest.upper()), digest)
        for bad in ("0" * 64, digest[:-1], "", None, "zz" * 32):
            with self.subTest(bad=bad), self.assertRaises(IntegrityVerificationError):
                verify_sha256(data, bad)


class TestEncryptedContentTamper(unittest.TestCase):
    def setUp(self):
        fixture_module.TestJWTEncryptedUploadIntegration.setUp(self)
        self.app.include_router(create_jwt_encrypted_download_router(
            db_path=self.db_path, storage_dir=self.storage_dir, key_directory=self.key_directory))

    def upload(self, user_id=101, document_id=1, filename=fixture_module.FILENAME, content=None):
        return self.client.post(
            f"/documents/{document_id}/encrypted-content", params={"filename": filename},
            content=self.content if content is None else content,
            headers={"Authorization": f"Bearer {create_access_token(user_id)}",
                     "Content-Type": "application/octet-stream"})

    def download(self, user_id=101, document_id=1):
        return self.client.get(f"/documents/{document_id}/encrypted-content",
                               headers={"Authorization": f"Bearer {create_access_token(user_id)}"})

    def sql(self, statement, params=()):
        with closing(sqlite3.connect(self.db_path)) as db, db:
            return db.execute(statement, params).fetchall()

    def ciphertext_path(self, document_id=1):
        storage_id = self.sql("SELECT storage_id FROM encrypted_document_keys WHERE document_id=?",
                              (document_id,))[0][0]
        return self.storage_dir / f"{storage_id}.svenc"

    def assertIntegrityFailure(self, response):
        self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(response.json()["detail"], "Document failed integrity verification")
        self.assertNotIn(self.content, response.content)

    def test_upload_records_fingerprint_and_download_returns_it(self):
        response = self.upload()
        self.assertEqual(response.status_code, 201, response.text)
        expected = hashlib.sha256(self.content).hexdigest()
        self.assertEqual(response.json()["sha256"], expected)
        self.assertEqual(self.sql("SELECT content_sha256 FROM encrypted_document_keys")[0][0], expected)
        result = self.download()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["x-content-sha256"], expected)

    def test_flipped_ciphertext_byte_is_rejected(self):
        self.assertEqual(self.upload().status_code, 201)
        path = self.ciphertext_path()
        data = bytearray(path.read_bytes())
        data[20] ^= 0x01
        path.write_bytes(bytes(data))
        self.assertIntegrityFailure(self.download())

    def test_truncated_ciphertext_is_rejected(self):
        self.assertEqual(self.upload().status_code, 201)
        path = self.ciphertext_path()
        path.write_bytes(path.read_bytes()[:-5])
        self.assertIntegrityFailure(self.download())

    def test_modified_recorded_fingerprint_is_rejected(self):
        self.assertEqual(self.upload().status_code, 201)
        self.sql("UPDATE encrypted_document_keys SET content_sha256=?", ("a" * 64,))
        self.assertIntegrityFailure(self.download())

    def test_tampered_wrapped_key_is_rejected(self):
        self.assertEqual(self.upload().status_code, 201)
        wrapped = bytearray(self.sql("SELECT wrapped_dek FROM encrypted_document_keys")[0][0])
        wrapped[0] ^= 0xFF
        self.sql("UPDATE encrypted_document_keys SET wrapped_dek=?", (bytes(wrapped),))
        self.assertIntegrityFailure(self.download())

    def test_swapped_ciphertext_files_fail_aad_binding(self):
        # Alice's and Bob's files are both valid ciphertexts, but each is bound
        # (AAD) to its own owner, document id, storage id and filename.
        self.assertEqual(self.upload().status_code, 201)
        self.assertEqual(self.upload(user_id=102, document_id=2,
                                     filename=fixture_module.OTHER_FILENAME).status_code, 201)
        alice, bob = self.ciphertext_path(1), self.ciphertext_path(2)
        alice_bytes, bob_bytes = alice.read_bytes(), bob.read_bytes()
        alice.write_bytes(bob_bytes)
        bob.write_bytes(alice_bytes)
        self.assertIntegrityFailure(self.download(101, 1))
        self.assertIntegrityFailure(self.download(102, 2))

    def test_reassigning_the_document_owner_breaks_decryption(self):
        self.assertEqual(self.upload().status_code, 201)
        self.sql("UPDATE owned_documents SET owner_user_id=102 WHERE id=1")
        self.assertIntegrityFailure(self.download(102, 1))

    def test_legacy_row_without_fingerprint_still_decrypts_and_is_backfilled(self):
        self.assertEqual(self.upload().status_code, 201)
        self.sql("UPDATE encrypted_document_keys SET content_sha256=NULL")
        first = self.download()
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.content, self.content)
        expected = hashlib.sha256(self.content).hexdigest()
        self.assertEqual(self.sql("SELECT content_sha256 FROM encrypted_document_keys")[0][0], expected)

    def test_pre_migration_table_is_upgraded_in_place(self):
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertFalse(has_content_sha256_column(db))
        self.assertEqual(self.upload().status_code, 201)
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertTrue(has_content_sha256_column(db))
        self.assertEqual(self.download().content, self.content)

    def test_upload_must_match_metadata_fingerprint(self):
        self.sql("ALTER TABLE owned_documents ADD COLUMN sha256 TEXT")
        self.sql("UPDATE owned_documents SET sha256=? WHERE id=1", ("b" * 64,))
        rejected = self.upload()
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("SHA-256", rejected.json()["detail"])
        self.assertEqual(list(self.storage_dir.glob("*.svenc")), [])
        self.sql("UPDATE owned_documents SET sha256=? WHERE id=1",
                 (hashlib.sha256(self.content).hexdigest(),))
        self.assertEqual(self.upload().status_code, 201)


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 17 + b"fictional-png-body"


class BinaryVaultCase(unittest.TestCase):
    """Shared temporary binary vault (DB, ciphertext dir, protected KEK)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / "bin").mkdir()
        (root / "keys").mkdir()
        save_protected_kek(root / "keys", "binary-test-kek", generate_kek())
        env = patch.dict(os.environ, {
            "SECUREVAULT_JWT_SECRET": secrets.token_urlsafe(48),
            "SECUREVAULT_BINARY_DB_PATH": str(root / "binary.db"),
            "SECUREVAULT_BINARY_STORAGE_DIR": str(root / "bin"),
            "SECUREVAULT_UPLOAD_KEK_DIR": str(root / "keys"),
            "SECUREVAULT_UPLOAD_KEK_ID": "binary-test-kek",
        })
        env.start()
        self.addCleanup(env.stop)
        vault_binary.initialize_binary_database()
        self.bin_dir = root / "bin"
        self.binary_db = root / "binary.db"
        users = patch("backend.app.api.auth.get_user_by_id",
                      lambda uid: {"id": uid, "username": f"user{uid}"} if uid in (101, 102) else None)
        users.start()
        self.addCleanup(users.stop)
        app = FastAPI()
        app.include_router(vault_binary.API)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def auth(self, user_id=101):
        return {"Authorization": f"Bearer {create_access_token(user_id)}"}

    def upload(self, filename="scan.png", body=PNG, user_id=101):
        headers = {**self.auth(user_id), "Content-Type": "application/octet-stream"}
        return self.client.post("/vault/binary/files", params={"filename": filename},
                                content=body, headers=headers)

    def download(self, file_id, user_id=101):
        return self.client.get(f"/vault/binary/files/{file_id}/download", headers=self.auth(user_id))

    def sql(self, statement, params=()):
        with closing(sqlite3.connect(self.binary_db)) as db, db:
            return db.execute(statement, params).fetchall()


class TestBinaryTamper(BinaryVaultCase):
    def test_round_trip_returns_fingerprint(self):
        created = self.upload()
        self.assertEqual(created.status_code, 201, created.text)
        result = self.download(created.json()["id"])
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content, PNG)
        self.assertEqual(result.headers["x-content-sha256"], hashlib.sha256(PNG).hexdigest())

    def test_flipped_ciphertext_byte_is_rejected(self):
        file_id = self.upload().json()["id"]
        path = next(self.bin_dir.glob("*.svbin"))
        data = bytearray(path.read_bytes())
        data[3] ^= 0x01
        path.write_bytes(bytes(data))
        response = self.download(file_id)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"], "Document failed integrity verification")

    def test_modified_fingerprint_is_rejected(self):
        file_id = self.upload().json()["id"]
        self.sql("UPDATE binary_documents SET sha256=?", ("c" * 64,))
        self.assertEqual(self.download(file_id).status_code, 500)

    def test_swapped_files_fail_aad_binding(self):
        one = self.upload("one.png").json()["id"]
        two = self.upload("two.png", body=PNG + b"-second").json()["id"]
        rows = dict(self.sql("SELECT id, storage_id FROM binary_documents"))
        p1, p2 = self.bin_dir / f"{rows[one]}.svbin", self.bin_dir / f"{rows[two]}.svbin"
        b1, b2 = p1.read_bytes(), p2.read_bytes()
        p1.write_bytes(b2)
        p2.write_bytes(b1)
        self.assertEqual(self.download(one).status_code, 500)
        self.assertEqual(self.download(two).status_code, 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
