"""Document-type validation, metadata routes, organiser and startup guards."""

import io
import os
import secrets
import sqlite3
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import api_main
from backend.app.api import private_documents, vault_organizer
from backend.app.core import settings
from backend.app.database.user_repository import register_user
from backend.app.security import document_types
from backend.app.security import encrypted_upload_acl_guard as acl_guard
from backend.app.security import encrypted_upload_identity_guard as identity_guard
from backend.app.security.encrypted_upload_registration import EncryptedUploadRegistrationError
from backend.app.security.tokens import create_access_token


def zip_bytes(entries, encrypted_flag=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    data = bytearray(buffer.getvalue())
    if encrypted_flag:
        # Set the "encrypted" general-purpose bit in every central-directory entry.
        offset = data.find(b"PK")
        while offset != -1:
            data[offset + 8] |= 0x01
            offset = data.find(b"PK", offset + 4)
    return bytes(data)


class TestDocumentTypes(unittest.TestCase):
    def test_accepts_well_formed_samples(self):
        docx = zip_bytes({"[Content_Types].xml": "<T/>", "word/document.xml": "<d/>"})
        xlsx = zip_bytes({"[Content_Types].xml": "<T/>", "xl/workbook.xml": "<w/>"})
        samples = {"a.txt": b"hello", "b.pdf": b"%PDF-1.7\n%%EOF", "c.docx": docx, "d.xlsx": xlsx,
                   "e.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20,
                   "f.JPEG": b"\xff\xd8xx\xff\xd9"}
        for name, data in samples.items():
            with self.subTest(name=name):
                media = document_types.validate_document(name, data)
                self.assertEqual(media, document_types.MEDIA_TYPES[Path(name).suffix.lower()])

    def test_rejects_bad_names(self):
        for name in ("CON.txt", "lpt1.backup.pdf", "../a.txt", "a/b.txt", "noext", "x.exe",
                     ".hidden.txt", "a..b.txt", "a" * 101 + ".txt", 42):
            with self.subTest(name=name), self.assertRaises(document_types.DocumentTypeError):
                document_types.validate_filename(name)

    def test_rejects_malformed_or_dangerous_containers(self):
        traversal = zip_bytes({"[Content_Types].xml": "<T/>", "word/document.xml": "<d/>",
                               "../evil.xml": "x"})
        encrypted = zip_bytes({"[Content_Types].xml": "<T/>", "word/document.xml": "<d/>"}, encrypted_flag=True)
        missing = zip_bytes({"[Content_Types].xml": "<T/>"})
        bomb = zip_bytes({"[Content_Types].xml": "<T/>", "word/document.xml": "<d/>",
                          "word/media/huge.bin": b"\x00" * (3 * 1024 * 1024)})
        for label, data in (("traversal", traversal), ("encrypted", encrypted),
                            ("missing parts", missing), ("ratio bomb", bomb), ("not a zip", b"PK-nope")):
            with self.subTest(label), self.assertRaises(document_types.DocumentTypeError):
                document_types.validate_document("x.docx", data)

    def test_rejects_wrong_content_and_size(self):
        with self.assertRaises(document_types.DocumentTypeError):
            document_types.validate_document("a.jpg", b"\xff\xd8 no end marker")
        with self.assertRaises(document_types.DocumentTypeError):
            document_types.validate_document("a.txt", b"nul\x00byte")
        with self.assertRaises(document_types.DocumentTypeError):
            document_types.validate_document("a.txt", b"x" * 11, max_bytes=10)
        with patch.dict(os.environ, {"SECUREVAULT_MAX_DOCUMENT_BYTES": str(60 * 1024 * 1024)}):
            with self.assertRaises(RuntimeError):
                document_types.max_document_bytes()


class MetadataCase(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": secrets.token_urlsafe(48)})
        env.start()
        self.addCleanup(env.stop)
        org = settings.org_db_path()
        org.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(org)):
            pass
        vault_organizer.initialize_sidecar(org)
        app = FastAPI()
        app.include_router(private_documents.router)
        app.include_router(vault_organizer.router)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.alice = register_user(f"meta_a_{secrets.token_hex(3)}", "Metadata-Password-11")
        self.bob = register_user(f"meta_b_{secrets.token_hex(3)}", "Metadata-Password-11")

    def auth(self, user_id):
        return {"Authorization": f"Bearer {create_access_token(user_id)}"}

    def create(self, user_id, name="notes.txt", content="hello"):
        response = self.client.post("/documents/private", headers=self.auth(user_id),
                                    json={"filename": name, "content": content})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()


class TestPrivateDocuments(MetadataCase):
    def test_pagination_and_owner_scoping(self):
        for index in range(5):
            self.create(self.alice, f"doc{index}.txt")
        self.create(self.bob, "bob.txt")
        page = self.client.get("/documents/private", params={"limit": 2, "offset": 2},
                               headers=self.auth(self.alice)).json()
        self.assertEqual(page["total"], 5)
        self.assertEqual(len(page["documents"]), 2)
        self.assertTrue(page["has_more"])
        self.assertTrue(all(d["owner_user_id"] == self.alice for d in page["documents"]))
        self.assertEqual(self.client.get("/documents/private", params={"limit": 101},
                                         headers=self.auth(self.alice)).status_code, 422)

    def test_metadata_records_sha256_and_validation(self):
        doc = self.create(self.alice, content="abc")
        self.assertEqual(doc["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(self.client.post("/documents/private", headers=self.auth(self.alice),
                                          json={"filename": "", "content": "x"}).status_code, 422)
        self.assertEqual(self.client.get("/documents/private").status_code, 401)

    def test_upload_check_validates_without_storing(self):
        response = self.client.post("/documents/private/upload/check", headers=self.auth(self.alice),
                                    files={"file": ("check.txt", b"plain text", "text/plain")})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["stored"])
        bad = self.client.post("/documents/private/upload/check", headers=self.auth(self.alice),
                               files={"file": ("check.exe", b"MZ", "application/octet-stream")})
        self.assertEqual(bad.status_code, 400)


class TestOrganizer(MetadataCase):
    def test_snapshot_and_update_are_owner_scoped(self):
        mine = self.create(self.alice)["id"]
        theirs = self.create(self.bob)["id"]
        saved = self.client.put(f"/vault/organize/documents/{mine}", headers=self.auth(self.alice),
                                json={"folder": "Finance", "tags": ["q1", "q1", "tax"], "favorite": True})
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual(saved.json()["tags"], ["q1", "tax"])
        snapshot = self.client.get("/vault/organize/snapshot", headers=self.auth(self.alice)).json()["items"]
        self.assertIn(str(mine), snapshot)
        self.assertNotIn(str(theirs), snapshot)
        self.assertEqual(snapshot[str(mine)]["folder"], "Finance")
        self.assertTrue(snapshot[str(mine)]["favorite"])
        self.assertFalse(snapshot[str(mine)]["has_encrypted_key_record"])
        other = self.client.put(f"/vault/organize/documents/{theirs}", headers=self.auth(self.alice),
                                json={"folder": "Stolen"})
        self.assertEqual(other.status_code, 404)

    def test_label_validation(self):
        doc = self.create(self.alice)["id"]
        for payload in ({"folder": "../etc"}, {"folder": "x" * 40}, {"tags": [f"t{i}" for i in range(9)]},
                        {"tags": ["<script>"]}):
            with self.subTest(payload=payload):
                response = self.client.put(f"/vault/organize/documents/{doc}", headers=self.auth(self.alice),
                                           json=payload)
                self.assertEqual(response.status_code, 422)


class TestLegacyAndHealthRoutes(unittest.TestCase):
    def test_retired_routes_return_410_and_health_is_public(self):
        with TestClient(api_main.create_app(settings.upload_environment())) as client:
            self.assertEqual(client.get("/health").json()["status"], "healthy")
            self.assertEqual(client.post("/documents/inspect",
                                         json={"filename": "a.txt", "content": "x"}).status_code, 410)


class TestStartupGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / "store").mkdir()
        (root / "keys").mkdir()
        (root / "main.db").write_bytes(b"")
        self.env = {"SECUREVAULT_UPLOAD_DB_PATH": str(root / "main.db"),
                    "SECUREVAULT_UPLOAD_STORAGE_DIR": str(root / "store"),
                    "SECUREVAULT_UPLOAD_KEK_DIR": str(root / "keys")}

    def test_broad_directory_access_is_refused_with_reason(self):
        broad = {"dacl_present": True, "broad_read": True, "broad_write": False}
        safe = {"dacl_present": True, "broad_read": False, "broad_write": False}
        with patch.object(acl_guard, "inspect_directory_acl", side_effect=[safe, broad]):
            with self.assertRaises(EncryptedUploadRegistrationError) as raised:
                acl_guard.validate_encrypted_upload_acls(self.env)
        self.assertIn("protected key directory", str(raised.exception))
        with patch.object(acl_guard, "inspect_directory_acl",
                          return_value={"dacl_present": True, "broad_read": False, "broad_write": True}):
            with self.assertRaises(EncryptedUploadRegistrationError) as raised:
                acl_guard.validate_encrypted_upload_acls(self.env)
        self.assertIn("storage directory", str(raised.exception))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_posix_group_readable_key_directory_is_refused(self):
        os.chmod(self.env["SECUREVAULT_UPLOAD_STORAGE_DIR"], 0o700)
        os.chmod(self.env["SECUREVAULT_UPLOAD_KEK_DIR"], 0o750)
        with self.assertRaises(EncryptedUploadRegistrationError):
            acl_guard.validate_encrypted_upload_acls(self.env)
        os.chmod(self.env["SECUREVAULT_UPLOAD_KEK_DIR"], 0o700)
        self.assertTrue(acl_guard.validate_encrypted_upload_acls(self.env)["acl_preflight_passed"])

    def test_wrong_process_identity_is_refused(self):
        if os.name == "nt":
            env = {"SECUREVAULT_UPLOAD_WINDOWS_SID": "S-1-5-21-1-2-3-1001"}
            with patch.object(identity_guard, "read_current_process_sid", return_value="S-1-5-21-9-9-9-1001"):
                with self.assertRaises(EncryptedUploadRegistrationError) as raised:
                    identity_guard.validate_windows_deployment_identity(env)
            self.assertIn("SECUREVAULT_UPLOAD_WINDOWS_SID", str(raised.exception))
            with self.assertRaises(EncryptedUploadRegistrationError):
                identity_guard.validate_windows_deployment_identity({})
        else:
            env = {"SECUREVAULT_UPLOAD_EXPECTED_UID": str(os.geteuid() + 1)}
            with self.assertRaises(EncryptedUploadRegistrationError) as raised:
                identity_guard.validate_windows_deployment_identity(env)
            self.assertIn("SECUREVAULT_UPLOAD_EXPECTED_UID", str(raised.exception))
            ok = identity_guard.validate_windows_deployment_identity(
                {"SECUREVAULT_UPLOAD_EXPECTED_UID": str(os.geteuid())})
            self.assertTrue(ok["identity_verified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
