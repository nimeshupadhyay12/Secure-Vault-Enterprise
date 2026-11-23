"""End-to-end: `manage setup` -> preflight -> full app -> encrypted documents.

Runs with the platform's default key provider (DPAPI on Windows, the
master-key provider elsewhere), so on Windows this also exercises the real
ACL and process-SID guards against directories that setup restricted.
"""

import hashlib
import io
import os
import secrets
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
from contextlib import closing, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import api_main, manage
from backend.app.core import bootstrap, settings
from backend.app.database.user_repository import register_user
from backend.app.security import document_types


def make_docx():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document>fictional</w:document>")
    return buffer.getvalue()


PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 17 + b"fictional"
JPEG = b"\xff\xd8\xff\xe0fictional-jpeg\xff\xd9"
TEXT = "Fictional quarterly notes - café\r\n".encode("utf-8")
DOCX = make_docx()
PASSWORD = "Setup-Flow-Password-77"


class SetupCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.mkdtemp(prefix="sv-setup-")
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.runtime = Path(self.temp) / "runtime"
        self.config = Path(self.temp) / "securevault.env"
        env = patch.dict(os.environ, {"SECUREVAULT_CONFIG_FILE": str(self.config)})
        env.start()
        self.addCleanup(env.stop)
        for name in ("SECUREVAULT_JWT_SECRET", "SECUREVAULT_UPLOAD_STORAGE_DIR", "SECUREVAULT_UPLOAD_KEK_DIR",
                     "SECUREVAULT_UPLOAD_KEK_ID", "SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD", "SECUREVAULT_AUDIT_KEY"):
            os.environ.pop(name, None)

    def setup_vault(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = manage.main(["setup", "--runtime-dir", str(self.runtime)])
        self.assertEqual(code, 0, out.getvalue())
        return out.getvalue()


class TestSetupCommand(SetupCase):
    def test_setup_creates_everything_and_preflight_passes(self):
        output = self.setup_vault()
        self.assertIn("PREFLIGHT OK", output)
        values = settings._read_config_file(self.config)
        for name in ("SECUREVAULT_JWT_SECRET", "SECUREVAULT_AUDIT_KEY", "SECUREVAULT_UPLOAD_KEK_DIR",
                     "SECUREVAULT_UPLOAD_STORAGE_DIR", "SECUREVAULT_UPLOAD_KEK_ID"):
            self.assertTrue(values.get(name), name)
        self.assertEqual(values["SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD"], "1")
        self.assertGreaterEqual(len(values["SECUREVAULT_JWT_SECRET"]), 48)
        key_files = list(Path(values["SECUREVAULT_UPLOAD_KEK_DIR"]).iterdir())
        self.assertEqual(len(key_files), 1)
        with closing(sqlite3.connect(values["SECUREVAULT_DB_PATH"])) as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            versions = {r[0] for r in db.execute("SELECT version FROM schema_migrations")}
        self.assertTrue({"users", "owned_documents", "encrypted_document_keys", "refresh_tokens",
                         "revoked_access_tokens", "auth_failures", "audit_log"} <= tables)
        self.assertTrue({1, 2, 3, 4} <= versions)
        with closing(sqlite3.connect(values["SECUREVAULT_BINARY_DB_PATH"])) as db:
            self.assertTrue(db.execute("SELECT 1 FROM sqlite_master WHERE name='binary_documents'").fetchone())
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(manage.main(["check"]), 0)
        self.assertIn("OK", out.getvalue())

    def test_setup_is_idempotent_and_never_replaces_the_kek(self):
        self.setup_vault()
        before = settings._read_config_file(self.config)
        key_file = next(Path(before["SECUREVAULT_UPLOAD_KEK_DIR"]).iterdir())
        key_bytes = key_file.read_bytes()
        output = self.setup_vault()
        self.assertIn("existing KEK verified", output)
        self.assertEqual(settings._read_config_file(self.config), before)
        self.assertEqual(key_file.read_bytes(), key_bytes)

    def test_env_provider_without_master_key_explains_what_to_do(self):
        with patch.dict(os.environ, {"SECUREVAULT_MASTER_KEY": ""}):
            with self.assertRaises(bootstrap.SetupError) as raised:
                bootstrap.run_setup(runtime_dir=self.runtime, provider="env", report=lambda *_: None)
        self.assertIn("SECUREVAULT_MASTER_KEY", str(raised.exception))

    def test_check_reports_the_reason_when_disabled_or_broken(self):
        ok, message = bootstrap.run_check()
        self.assertFalse(ok)
        self.setup_vault()
        values = settings._read_config_file(self.config)
        with patch.dict(os.environ, {"SECUREVAULT_UPLOAD_KEK_ID": "missing-key"}):
            ok, message = bootstrap.run_check()
        self.assertFalse(ok)
        self.assertIn("missing-key", message)
        with patch.dict(os.environ, {"SECUREVAULT_UPLOAD_STORAGE_DIR": values["SECUREVAULT_UPLOAD_KEK_DIR"]}):
            ok, message = bootstrap.run_check()
        self.assertFalse(ok)
        self.assertIn("nesting", message)


class TestStartupModes(SetupCase):
    def test_disabled_mode_has_no_encrypted_routes(self):
        app = api_main.create_app(settings.upload_environment())
        paths = {route.path for route in app.routes}
        self.assertNotIn("/documents/encrypted", paths)
        self.assertNotIn("/vault/binary/files", paths)
        with TestClient(app) as client:
            self.assertEqual(client.get("/vault/status").json(), {"encrypted_upload_enabled": False})

    def test_enabled_but_unconfigured_fails_with_a_clear_message(self):
        with patch.dict(os.environ, {"SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD": "1"}):
            with self.assertRaises(RuntimeError) as raised:
                api_main.create_app(settings.upload_environment())
        message = str(raised.exception)
        self.assertIn("is not set", message)
        self.assertIn("backend.manage", message)

    def test_invalid_activation_value_refused(self):
        with patch.dict(os.environ, {"SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD": "yes"}):
            with self.assertRaises(RuntimeError):
                api_main.create_app(settings.upload_environment())


class TestEncryptedDocumentsEndToEnd(SetupCase):
    def setUp(self):
        super().setUp()
        self.setup_vault()
        self.app = api_main.create_app(settings.upload_environment())
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)
        self.alice = f"alice_{secrets.token_hex(3)}"
        self.bob = f"bob_{secrets.token_hex(3)}"
        register_user(self.alice, PASSWORD)
        register_user(self.bob, PASSWORD)

    def login(self, username):
        response = self.client.post("/auth/token", json={"username": username, "password": PASSWORD})
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def upload(self, headers, filename, body):
        return self.client.post("/documents/encrypted", params={"filename": filename}, content=body,
                                headers={**headers, "Content-Type": "application/octet-stream"})

    def test_every_supported_type_round_trips_encrypted(self):
        alice = self.login(self.alice)
        storage = Path(settings._read_config_file(self.config)["SECUREVAULT_UPLOAD_STORAGE_DIR"])
        samples = {"notes.txt": TEXT, "report.pdf": PDF, "letter.docx": DOCX,
                   "scan.png": PNG, "photo.jpg": JPEG}
        for filename, body in samples.items():
            with self.subTest(filename=filename):
                created = self.upload(alice, filename, body)
                self.assertEqual(created.status_code, 201, created.text)
                data = created.json()
                self.assertEqual(data["sha256"], hashlib.sha256(body).hexdigest())
                self.assertEqual(data["media_type"], document_types.MEDIA_TYPES[Path(filename).suffix])
                result = self.client.get(f"/documents/{data['id']}/encrypted-content", headers=alice)
                self.assertEqual(result.status_code, 200, result.text)
                self.assertEqual(result.content, body)
                self.assertEqual(result.headers["x-content-sha256"], data["sha256"])
                self.assertEqual(result.headers["content-type"], "application/octet-stream")
        ciphertexts = b"".join(p.read_bytes() for p in storage.glob("*.svenc"))
        for body in samples.values():
            self.assertNotIn(body[:24], ciphertexts)
        listing = self.client.get("/documents/private", headers=alice).json()
        self.assertEqual(listing["total"], len(samples))

    def test_rejected_uploads(self):
        alice = self.login(self.alice)
        self.assertEqual(self.upload(alice, "evil.exe", b"MZ").status_code, 422)
        self.assertEqual(self.upload(alice, "fake.pdf", PNG).status_code, 422)  # content does not match type
        self.assertEqual(self.upload(alice, "bad.txt", b"\xff\xfe\x00").status_code, 422)
        self.assertEqual(self.upload(alice, "../x.txt", TEXT).status_code, 422)
        self.assertEqual(self.upload(alice, "empty.txt", b"").status_code, 400)
        with patch.dict(os.environ, {"SECUREVAULT_MAX_DOCUMENT_BYTES": "64"}):
            self.assertEqual(self.upload(alice, "big.txt", b"a" * 65).status_code, 413)
        anonymous = self.client.post("/documents/encrypted", params={"filename": "a.txt"}, content=TEXT,
                                     headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(anonymous.status_code, 401)
        self.assertEqual(self.client.get("/documents/private", headers=alice).json()["total"], 0)

    def test_owner_scoping_rename_block_and_delete(self):
        alice, bob = self.login(self.alice), self.login(self.bob)
        doc = self.upload(alice, "private.txt", TEXT).json()["id"]
        self.assertEqual(self.client.get(f"/documents/{doc}/encrypted-content", headers=bob).status_code, 404)
        self.assertEqual(self.client.get(f"/documents/private/{doc}", headers=bob).status_code, 404)
        self.assertEqual(self.client.delete(f"/documents/private/{doc}", headers=bob).status_code, 404)
        renamed = self.client.patch(f"/documents/private/{doc}", headers=alice, json={"filename": "other.txt"})
        self.assertEqual(renamed.status_code, 409)
        storage = Path(settings._read_config_file(self.config)["SECUREVAULT_UPLOAD_STORAGE_DIR"])
        self.assertEqual(len(list(storage.glob("*.svenc"))), 1)
        self.assertEqual(self.client.delete(f"/documents/private/{doc}", headers=alice).status_code, 200)
        self.assertEqual(list(storage.glob("*.svenc")), [])
        self.assertEqual(self.client.get(f"/documents/{doc}/encrypted-content", headers=alice).status_code, 404)

    def test_binary_vault_and_status_are_enabled(self):
        alice = self.login(self.alice)
        self.assertEqual(self.client.get("/vault/status").json(), {"encrypted_upload_enabled": True})
        created = self.client.post("/vault/binary/files", params={"filename": "scan.png"}, content=PNG,
                                   headers={**alice, "Content-Type": "application/octet-stream"})
        self.assertEqual(created.status_code, 201, created.text)
        listing = self.client.get("/vault/binary/files", headers=alice).json()
        self.assertEqual(listing["total"], 1)
        bob = self.login(self.bob)
        self.assertEqual(self.client.get(f"/vault/binary/files/{created.json()['id']}/download",
                                         headers=bob).status_code, 404)
        self.assertEqual(self.client.delete(f"/vault/binary/files/{created.json()['id']}",
                                            headers=alice).status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
