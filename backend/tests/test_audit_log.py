"""Tamper-evident audit log: chaining, verification, HMAC mode, API wiring."""

import io
import os
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import manage
from backend.app.api import private_documents, vault_organizer
from backend.app.database.db import initialize_database
from backend.app.security import audit_log
from backend.app.security.tokens import create_access_token


class AuditDbCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "audit.db"
        initialize_database(self.db)
        env = patch.dict(os.environ, {"SECUREVAULT_AUDIT_KEY": ""})
        env.start()
        self.addCleanup(env.stop)

    def record(self, event="login_success", **kwargs):
        return audit_log.record_event(event, db_path=self.db, **kwargs)

    def sql(self, statement, params=()):
        with closing(sqlite3.connect(self.db)) as db, db:
            return db.execute(statement, params).fetchall()


class TestAuditChain(AuditDbCase):
    def test_entries_chain_and_verify(self):
        ids = [self.record(user_id=1), self.record("logout", user_id=1),
               self.record("document_created", user_id=2, document_id=9)]
        self.assertTrue(all(ids))
        report = audit_log.verify_chain(self.db)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["entries"], 3)
        rows = self.sql("SELECT prev_hash, entry_hash FROM audit_log ORDER BY id")
        self.assertEqual(rows[0][0], audit_log.GENESIS_HASH)
        self.assertEqual(rows[1][0], rows[0][1])
        self.assertEqual(report["head_hash"], rows[-1][1])

    def test_modified_entry_is_detected(self):
        self.record(user_id=1)
        second = self.record("login_failure", outcome="failure", detail={"username": "eve"})
        self.record(user_id=1)
        self.sql("UPDATE audit_log SET detail=? WHERE id=?", ('{"username":"mallory"}', second))
        report = audit_log.verify_chain(self.db)
        self.assertFalse(report["ok"])
        self.assertEqual(report["first_bad_id"], second)
        self.assertIn("modified", report["reason"])

    def test_deleted_or_reordered_entry_is_detected(self):
        first, second, third = (self.record(user_id=n) for n in (1, 2, 3))
        self.sql("DELETE FROM audit_log WHERE id=?", (second,))
        report = audit_log.verify_chain(self.db)
        self.assertFalse(report["ok"])
        self.assertEqual(report["first_bad_id"], third)
        self.assertIn("chain broken", report["reason"])

    def test_hmac_mode_requires_the_key(self):
        key = secrets.token_urlsafe(40)
        with patch.dict(os.environ, {"SECUREVAULT_AUDIT_KEY": key}):
            self.record(user_id=1)
            self.assertEqual(self.sql("SELECT mac_alg FROM audit_log")[0][0], "hmac-sha256")
            self.assertTrue(audit_log.verify_chain(self.db)["ok"])
        self.assertFalse(audit_log.verify_chain(self.db)["ok"])
        with patch.dict(os.environ, {"SECUREVAULT_AUDIT_KEY": secrets.token_urlsafe(40)}):
            self.assertFalse(audit_log.verify_chain(self.db)["ok"])

    def test_invalid_events_are_not_recorded_and_never_raise(self):
        self.assertIsNone(self.record("made_up_event"))
        self.assertIsNone(self.record(outcome="maybe"))
        self.assertIsNone(self.record(detail={"blob": "x" * 5000}))
        self.assertIsNone(audit_log.record_event("logout", db_path=Path(self.temp.name) / "missing.db"))
        self.assertEqual(audit_log.verify_chain(self.db)["entries"], 0)

    def test_user_view_is_owner_scoped_and_hides_key_events(self):
        self.record(user_id=1)
        self.record("kek_created", user_id=1)
        self.record(user_id=2)
        events = audit_log.list_user_events(1, db_path=self.db)
        self.assertEqual([e["event_type"] for e in events], ["login_success"])

    def test_manage_audit_verify_exit_codes(self):
        self.record(user_id=1)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(manage.main(["audit-verify", "--db", str(self.db)]), 0)
        self.assertIn("Audit chain OK", out.getvalue())
        self.sql("UPDATE audit_log SET outcome='failure'")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(manage.main(["audit-verify", "--db", str(self.db)]), 1)


class TestAuditWiring(unittest.TestCase):
    """Routes write audit events into the main database."""

    def setUp(self):
        env = patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": secrets.token_urlsafe(48)})
        env.start()
        self.addCleanup(env.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        from backend.app.database.user_repository import register_user
        self.user_id = register_user(f"auditor_{secrets.token_hex(4)}", "Audit-Trail-Password-1")
        app = FastAPI()
        app.include_router(private_documents.router)
        app.include_router(vault_organizer.router)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.headers = {"Authorization": f"Bearer {create_access_token(self.user_id)}"}

    def events(self):
        return [e["event_type"] for e in reversed(audit_log.list_user_events(self.user_id, limit=100))]

    def test_document_lifecycle_and_activity_feed(self):
        self.assertIn("user_created", self.events())
        created = self.client.post("/documents/private", headers=self.headers,
                                   json={"filename": "notes.txt", "content": "hello"})
        self.assertEqual(created.status_code, 201, created.text)
        doc = created.json()["id"]
        self.assertEqual(self.client.patch(f"/documents/private/{doc}", headers=self.headers,
                                           json={"filename": "renamed.txt"}).status_code, 200)
        self.assertEqual(self.client.delete(f"/documents/private/{doc}", headers=self.headers).status_code, 200)
        self.assertEqual(self.events()[-3:], ["document_created", "document_renamed", "document_deleted"])
        feed = self.client.get("/vault/organize/activity", headers=self.headers)
        self.assertEqual(feed.status_code, 200)
        self.assertEqual(feed.json()["events"][0]["event_type"], "document_deleted")
        self.assertTrue(audit_log.verify_chain()["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
