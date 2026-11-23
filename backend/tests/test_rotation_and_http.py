"""KEK rotation (re-wrap without re-encrypting) and HTTP hardening."""

import io
import os
import secrets
import sqlite3
from contextlib import closing, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import test_setup_and_documents as setup_tests

from backend import api_main, manage
from backend.app.core import settings
from backend.app.database.user_repository import register_user
from backend.app.security import audit_log


class TestKekRotation(setup_tests.SetupCase):
    def setUp(self):
        super().setUp()
        # Private databases: rotation walks every row, so rows written by
        # other tests (under other temporary KEKs) must not be visible here.
        isolated = Path(self.temp) / "isolated"
        os.environ.update({
            "SECUREVAULT_DB_PATH": str(isolated / "main.db"),
            "SECUREVAULT_ORG_DB_PATH": str(isolated / "org.db"),
            "SECUREVAULT_BINARY_DB_PATH": str(isolated / "binary.db"),
            "SECUREVAULT_BINARY_STORAGE_DIR": str(isolated / "binary-files"),
        })
        self.setup_vault()
        self.values = settings._read_config_file(self.config)
        self.user_id = register_user(f"rot_{secrets.token_hex(3)}", setup_tests.PASSWORD,
                                     db_path=self.values["SECUREVAULT_DB_PATH"])

    def client_and_auth(self):
        # Users live in this test's private database; tokens are minted directly.
        from backend.app.database.user_repository import get_user_by_id
        from backend.app.security.tokens import create_access_token

        db = self.values["SECUREVAULT_DB_PATH"]
        lookup = patch("backend.app.api.auth.get_user_by_id", lambda uid: get_user_by_id(uid, db_path=db))
        lookup.start()
        self.addCleanup(lookup.stop)
        client = TestClient(api_main.create_app(settings.upload_environment()))
        self.addCleanup(client.close)
        return client, {"Authorization": f"Bearer {create_access_token(self.user_id)}"}

    def test_rotation_rewraps_keys_without_touching_ciphertext(self):
        client, auth = self.client_and_auth()
        octet = {**auth, "Content-Type": "application/octet-stream"}
        doc = client.post("/documents/encrypted", params={"filename": "a.pdf"},
                          content=setup_tests.PDF, headers=octet).json()["id"]
        binary = client.post("/vault/binary/files", params={"filename": "b.png"},
                             content=setup_tests.PNG, headers=octet).json()["id"]
        storage = Path(self.values["SECUREVAULT_UPLOAD_STORAGE_DIR"])
        binary_dir = Path(self.values["SECUREVAULT_BINARY_STORAGE_DIR"])
        files_before = {p.name: p.read_bytes() for d in (storage, binary_dir) for p in d.iterdir()}
        with closing(sqlite3.connect(self.values["SECUREVAULT_DB_PATH"])) as db:
            wrapped_before = db.execute("SELECT wrapped_dek FROM encrypted_document_keys WHERE document_id=?",
                                        (doc,)).fetchone()[0]

        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(manage.main(["rotate-kek", "--new-key-id", "securevault-kek-2"]), 0)
        self.assertIn("no ciphertext file was touched", out.getvalue())

        self.assertEqual(settings._read_config_file(self.config)["SECUREVAULT_UPLOAD_KEK_ID"], "securevault-kek-2")
        files_after = {p.name: p.read_bytes() for d in (storage, binary_dir) for p in d.iterdir()}
        self.assertEqual(files_before, files_after)
        with closing(sqlite3.connect(self.values["SECUREVAULT_DB_PATH"])) as db:
            key_id, wrapped_after = db.execute(
                "SELECT key_id, wrapped_dek FROM encrypted_document_keys WHERE document_id=?", (doc,)).fetchone()
        self.assertEqual(key_id, "securevault-kek-2")
        self.assertNotEqual(wrapped_before, wrapped_after)
        key_files = sorted(p.stem for p in Path(self.values["SECUREVAULT_UPLOAD_KEK_DIR"]).iterdir())
        self.assertEqual(key_files, ["securevault-kek-1", "securevault-kek-2"])

        # A freshly started app (new active KEK) still decrypts both documents.
        client, auth = self.client_and_auth()
        self.assertEqual(client.get(f"/documents/{doc}/encrypted-content", headers=auth).content, setup_tests.PDF)
        self.assertEqual(client.get(f"/vault/binary/files/{binary}/download", headers=auth).content,
                         setup_tests.PNG)
        self.assertTrue(audit_log.verify_chain(self.values["SECUREVAULT_DB_PATH"])["ok"])

    def test_rotation_refuses_same_id_and_tampered_rows(self):
        with redirect_stdout(io.StringIO()), patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(manage.main(["rotate-kek", "--new-key-id", "securevault-kek-1"]), 1)
        client, auth = self.client_and_auth()
        client.post("/documents/encrypted", params={"filename": "a.txt"}, content=b"hello",
                    headers={**auth, "Content-Type": "application/octet-stream"})
        with closing(sqlite3.connect(self.values["SECUREVAULT_DB_PATH"])) as db, db:
            db.execute("UPDATE encrypted_document_keys SET wrapped_dek = zeroblob(48)")
        with redirect_stdout(io.StringIO()), patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(manage.main(["rotate-kek", "--new-key-id", "securevault-kek-9"]), 1)
        self.assertIn("failed authentication", err.getvalue())
        self.assertEqual(settings._read_config_file(self.config)["SECUREVAULT_UPLOAD_KEK_ID"], "securevault-kek-1")


class TestHttpHardening(setup_tests.SetupCase):
    def make_client(self, **env):
        with patch.dict(os.environ, env):
            client = TestClient(api_main.create_app(settings.upload_environment()))
        self.addCleanup(client.close)
        return client

    def test_security_headers_on_api_and_ui(self):
        client = self.make_client()
        health = client.get("/health")
        self.assertEqual(health.headers["x-frame-options"], "DENY")
        self.assertEqual(health.headers["x-content-type-options"], "nosniff")
        self.assertEqual(health.headers["referrer-policy"], "no-referrer")
        self.assertIn("default-src 'none'", health.headers["content-security-policy"])
        self.assertNotIn("strict-transport-security", health.headers)
        page = client.get("/vault")
        self.assertIn("script-src 'self'", page.headers["content-security-policy"])
        token = client.post("/auth/token", json={"username": "nobody_here", "password": "x" * 12})
        self.assertEqual(token.headers["cache-control"], "no-store")

    def test_hsts_and_docs_toggle(self):
        client = self.make_client(SECUREVAULT_HSTS="1", SECUREVAULT_ENABLE_DOCS="0")
        self.assertIn("max-age=", client.get("/health").headers["strict-transport-security"])
        self.assertEqual(client.get("/docs").status_code, 404)
        self.assertEqual(client.get("/openapi.json").status_code, 404)

    def test_request_size_cap(self):
        client = self.make_client(SECUREVAULT_MAX_REQUEST_BYTES="2048")
        response = client.post("/auth/token", content=b"x" * 4096, headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 413)

        def chunks():
            for _ in range(4):
                yield b"x" * 1024
        streamed = client.post("/auth/token", content=chunks(), headers={"Content-Type": "application/json"})
        self.assertEqual(streamed.status_code, 413)

    def test_cors_is_same_origin_unless_configured(self):
        client = self.make_client()
        preflight = {"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"}
        self.assertNotIn("access-control-allow-origin", client.options("/auth/token", headers=preflight).headers)
        client = self.make_client(SECUREVAULT_CORS_ORIGINS="https://vault.example")
        allowed = client.options("/auth/token", headers={**preflight, "Origin": "https://vault.example"})
        self.assertEqual(allowed.headers["access-control-allow-origin"], "https://vault.example")
        self.assertNotIn("access-control-allow-credentials", allowed.headers)
        denied = client.get("/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("access-control-allow-origin", denied.headers)
