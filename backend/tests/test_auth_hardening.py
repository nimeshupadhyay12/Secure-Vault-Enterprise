"""Authentication hardening: /auth/token, lockout, refresh rotation, logout.

Uses the throw-away database configured by conftest.py.
"""

import os
import secrets
import sqlite3
import time
import unittest
from contextlib import closing
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.api import auth as auth_module
from backend.app.database import user_repository
from backend.app.database.db import DATABASE_PATH
from backend.app.database.user_repository import register_user


def _unique(prefix):
    return f"{prefix}_{secrets.token_hex(4)}"


PASSWORD = "Correct-Horse-Battery-42"


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": secrets.token_urlsafe(48)})
        env.start()
        self.addCleanup(env.stop)
        app = FastAPI()
        app.include_router(auth_module.router)
        self.client = TestClient(app)
        self.addCleanup(self.client.close)
        self.username = _unique("alice")
        self.user_id = register_user(self.username, PASSWORD)

    def login(self, password=PASSWORD, username=None, path="/auth/token"):
        return self.client.post(path, json={"username": username or self.username, "password": password})

    def bearer(self, token):
        return {"Authorization": f"Bearer {token}"}


class TestTokenEndpoint(AuthTestCase):
    def test_token_issues_access_and_refresh_pair(self):
        response = self.login()
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["expires_in"], 900)
        self.assertGreaterEqual(len(data["refresh_token"]), 40)
        self.assertEqual(response.headers["cache-control"], "no-store")
        me = self.client.get("/auth/me", headers=self.bearer(data["access_token"]))
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["username"], self.username)

    def test_unknown_user_and_wrong_password_look_identical(self):
        with patch.object(user_repository, "burn_dummy_verification",
                          wraps=user_repository.burn_dummy_verification) as dummy:
            unknown = self.login(username=_unique("nobody"))
            self.assertEqual(dummy.call_count, 1)
            wrong = self.login(password="Wrong-password-123")
            self.assertEqual(dummy.call_count, 1)
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(unknown.json(), wrong.json())

    def test_legacy_login_alias_runs_the_same_code_path(self):
        response = self.login(path="/auth/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())
        self.assertNotIn("message", response.json())
        self.assertEqual(self.login(path="/auth/login", password="nope-nope-nope").status_code, 401)

    def test_token_service_unconfigured_returns_503(self):
        with patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": "short"}):
            self.assertEqual(self.login().status_code, 503)

    def test_missing_and_garbage_bearer_rejected(self):
        self.assertEqual(self.client.get("/auth/me").status_code, 401)
        self.assertEqual(self.client.get("/auth/me", headers=self.bearer("a.b.c")).status_code, 401)


class TestLockout(AuthTestCase):
    def setUp(self):
        super().setUp()
        env = patch.dict(os.environ, {"SECUREVAULT_LOGIN_MAX_FAILURES": "3",
                                      "SECUREVAULT_LOGIN_LOCKOUT_SECONDS": "600"})
        env.start()
        self.addCleanup(env.stop)

    def test_lockout_after_repeated_failures_blocks_even_correct_password(self):
        for _ in range(3):
            self.assertEqual(self.login(password="Wrong-password-123").status_code, 401)
        locked = self.login()
        self.assertEqual(locked.status_code, 429)
        self.assertGreater(int(locked.headers["retry-after"]), 0)

    def test_unknown_usernames_are_locked_too(self):
        ghost = _unique("ghost")
        for _ in range(3):
            self.assertEqual(self.login(username=ghost, password="x" * 12).status_code, 401)
        self.assertEqual(self.login(username=ghost, password="x" * 12).status_code, 429)

    def test_success_resets_failure_counter(self):
        self.assertEqual(self.login(password="Wrong-password-123").status_code, 401)
        self.assertEqual(self.login(password="Wrong-password-123").status_code, 401)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.login(password="Wrong-password-123").status_code, 401)
        self.assertEqual(self.login(password="Wrong-password-123").status_code, 401)
        self.assertEqual(self.login().status_code, 200)


class TestRefreshAndLogout(AuthTestCase):
    def refresh(self, token):
        return self.client.post("/auth/refresh", json={"refresh_token": token})

    def test_refresh_rotates_token(self):
        first = self.login().json()
        rotated = self.refresh(first["refresh_token"])
        self.assertEqual(rotated.status_code, 200, rotated.text)
        second = rotated.json()
        self.assertNotEqual(second["refresh_token"], first["refresh_token"])
        self.assertEqual(self.client.get("/auth/me", headers=self.bearer(second["access_token"])).status_code, 200)

    def test_reused_refresh_token_revokes_the_whole_family(self):
        first = self.login().json()
        second = self.refresh(first["refresh_token"]).json()
        # Attacker replays the stolen, already-used token.
        self.assertEqual(self.refresh(first["refresh_token"]).status_code, 401)
        # The legitimate holder's newer token is now dead too.
        self.assertEqual(self.refresh(second["refresh_token"]).status_code, 401)

    def test_unknown_and_expired_refresh_tokens_rejected(self):
        self.assertEqual(self.refresh(secrets.token_urlsafe(32)).status_code, 401)
        token = self.login().json()["refresh_token"]
        with closing(sqlite3.connect(DATABASE_PATH)) as db, db:
            db.execute("UPDATE refresh_tokens SET expires_at = ? WHERE user_id = ?",
                       (int(time.time()) - 1, self.user_id))
        self.assertEqual(self.refresh(token).status_code, 401)

    def test_refresh_tokens_are_stored_hashed(self):
        token = self.login().json()["refresh_token"]
        with closing(sqlite3.connect(DATABASE_PATH)) as db:
            hashes = [row[0] for row in db.execute(
                "SELECT token_hash FROM refresh_tokens WHERE user_id = ?", (self.user_id,))]
        self.assertTrue(hashes)
        self.assertNotIn(token, hashes)

    def test_logout_revokes_access_token_and_refresh_family(self):
        pair = self.login().json()
        out = self.client.post("/auth/logout", headers=self.bearer(pair["access_token"]),
                               json={"refresh_token": pair["refresh_token"]})
        self.assertEqual(out.status_code, 200, out.text)
        self.assertEqual(out.json()["refresh_sessions_revoked"], 1)
        self.assertEqual(self.client.get("/auth/me", headers=self.bearer(pair["access_token"])).status_code, 401)
        self.assertEqual(self.refresh(pair["refresh_token"]).status_code, 401)

    def test_logout_all_sessions(self):
        one = self.login().json()
        two = self.login().json()
        out = self.client.post("/auth/logout", headers=self.bearer(one["access_token"]),
                               json={"all_sessions": True})
        self.assertEqual(out.status_code, 200)
        self.assertEqual(self.refresh(one["refresh_token"]).status_code, 401)
        self.assertEqual(self.refresh(two["refresh_token"]).status_code, 401)
        # The other session's access token stays valid until it expires (<= 15 min).
        self.assertEqual(self.client.get("/auth/me", headers=self.bearer(two["access_token"])).status_code, 200)

    def test_logout_cannot_revoke_another_users_refresh_family(self):
        mine = self.login().json()
        other_name = _unique("bob")
        register_user(other_name, PASSWORD)
        theirs = self.login(username=other_name).json()
        out = self.client.post("/auth/logout", headers=self.bearer(mine["access_token"]),
                               json={"refresh_token": theirs["refresh_token"]})
        self.assertEqual(out.json()["refresh_sessions_revoked"], 0)
        self.assertEqual(self.refresh(theirs["refresh_token"]).status_code, 200)

    def test_logout_requires_authentication(self):
        self.assertEqual(self.client.post("/auth/logout").status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
