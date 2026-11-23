"""JWT validation, Argon2id parameters, password policy, key providers, settings."""

import base64
import os
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import jwt
from argon2 import PasswordHasher

from backend.app.core import settings
from backend.app.database.db import DATABASE_PATH
from backend.app.database.user_repository import authenticate_user, register_user
from backend.app.security import key_provider, passwords, tokens
from backend.app.security.key_wrapping import generate_kek
from backend.app.security.windows_kek_store import load_protected_kek, save_protected_kek


SECRET = secrets.token_urlsafe(48)


def _claims(**overrides):
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "7", "iss": tokens.ISSUER, "aud": tokens.AUDIENCE, "iat": now, "nbf": now,
        "exp": now + timedelta(minutes=5), "jti": secrets.token_hex(16), "typ": "access",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


class TestAccessTokens(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": SECRET})
        env.start()
        self.addCleanup(env.stop)

    def forge(self, algorithm="HS256", key=SECRET, **overrides):
        return jwt.encode(_claims(**overrides), key, algorithm=algorithm)

    def test_round_trip_contains_all_required_claims(self):
        claims = tokens.decode_access_claims(tokens.create_access_token(7))
        for name in tokens.REQUIRED_CLAIMS:
            self.assertIn(name, claims)
        self.assertEqual(claims["user_id"], 7)
        self.assertLessEqual(claims["exp"] - claims["iat"], 900)

    def test_alg_none_and_other_algorithms_rejected(self):
        unsigned = jwt.encode(_claims(), None, algorithm="none")
        with self.assertRaises(jwt.InvalidTokenError):
            tokens.decode_access_claims(unsigned)
        with self.assertRaises(jwt.InvalidTokenError):
            tokens.decode_access_claims(self.forge(algorithm="HS512"))

    def test_wrong_issuer_audience_type_or_key_rejected(self):
        for token in (self.forge(iss="evil"), self.forge(aud="other-api"),
                      self.forge(typ="refresh"), self.forge(key=secrets.token_urlsafe(48))):
            with self.subTest(token=token[:20]), self.assertRaises(jwt.InvalidTokenError):
                tokens.decode_access_claims(token)

    def test_expired_future_and_missing_claims_rejected(self):
        past = datetime.now(timezone.utc) - timedelta(minutes=30)
        future = datetime.now(timezone.utc) + timedelta(minutes=30)
        for token in (self.forge(exp=past, iat=past - timedelta(minutes=1), nbf=past - timedelta(minutes=1)),
                      self.forge(nbf=future), self.forge(jti=None), self.forge(iat=None)):
            with self.subTest(), self.assertRaises(jwt.InvalidTokenError):
                tokens.decode_access_claims(token)

    def test_non_numeric_subject_rejected(self):
        with self.assertRaises(ValueError):
            tokens.decode_access_claims(self.forge(sub="admin"))

    def test_lifetime_capped_at_15_minutes(self):
        with self.assertRaises(ValueError):
            tokens.create_access_token(1, lifetime_seconds=901)
        with self.assertRaises(ValueError):
            tokens.create_access_token(True)

    def test_short_and_placeholder_secrets_refused_outside_development(self):
        with patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": "x" * 10}):
            with self.assertRaises(RuntimeError):
                tokens.get_token_secret()
        placeholder = "change-me-to-a-long-random-secret-value-1234"
        with patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": placeholder, "SECUREVAULT_ENV": "production"}):
            with self.assertRaises(RuntimeError):
                tokens.get_token_secret()
        with patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": placeholder, "SECUREVAULT_ENV": "development"}):
            self.assertEqual(tokens.get_token_secret(), placeholder)

    def test_development_mode_uses_ephemeral_random_secret(self):
        with patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": "", "SECUREVAULT_ENV": "development"}):
            first = tokens.get_token_secret()
            self.assertGreaterEqual(len(first), 32)
            self.assertEqual(first, tokens.get_token_secret())
        with patch.dict(os.environ, {"SECUREVAULT_JWT_SECRET": "", "SECUREVAULT_ENV": "production"}):
            with self.assertRaises(RuntimeError):
                tokens.get_token_secret()


class TestPasswords(unittest.TestCase):
    def test_argon2id_parameters_are_pinned_in_the_encoded_hash(self):
        encoded = passwords.hash_password("Some-Long-Password-1")
        self.assertTrue(encoded.startswith("$argon2id$v=19$m=65536,t=3,p=4$"), encoded)
        self.assertFalse(passwords.needs_rehash(encoded))
        self.assertTrue(passwords.verify_password(encoded, "Some-Long-Password-1"))
        self.assertFalse(passwords.verify_password(encoded, "wrong"))

    def test_login_upgrades_hashes_made_with_weaker_parameters(self):
        username = f"legacy_{secrets.token_hex(4)}"
        register_user(username, "Legacy-Password-123")
        weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("Legacy-Password-123")
        self.assertTrue(passwords.needs_rehash(weak))
        with closing(sqlite3.connect(DATABASE_PATH)) as db, db:
            db.execute("UPDATE users SET password_hash = ? WHERE username = ?", (weak, username))
        self.assertIsNotNone(authenticate_user(username, "Legacy-Password-123"))
        with closing(sqlite3.connect(DATABASE_PATH)) as db:
            upgraded = db.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()[0]
        self.assertNotEqual(upgraded, weak)
        self.assertTrue(upgraded.startswith("$argon2id$v=19$m=65536,t=3,p=4$"))

    def test_password_policy(self):
        self.assertEqual(passwords.password_policy_errors("A-very-decent-passphrase"), [])
        self.assertTrue(passwords.password_policy_errors("short"))
        self.assertTrue(passwords.password_policy_errors("password123"))
        self.assertTrue(passwords.password_policy_errors("aaaaaaaaaaaaaaaa"))
        self.assertTrue(passwords.password_policy_errors("carol-is-the-best-1", username="carol"))
        self.assertTrue(passwords.password_policy_errors("x" * 1025))
        with self.assertRaises(ValueError):
            register_user(f"weak_{secrets.token_hex(3)}", "password")
        with self.assertRaises(ValueError):
            register_user("../etc/passwd", "A-very-decent-passphrase")

    def test_oversized_password_rejected_without_hashing(self):
        from backend.app.database import user_repository
        with patch.object(user_repository, "verify_password") as verify,                 patch.object(user_repository, "burn_dummy_verification") as dummy:
            self.assertIsNone(authenticate_user("anyone", "x" * 5000))
            verify.assert_not_called()
            dummy.assert_not_called()


class TestKeyProviders(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.master = secrets.token_bytes(32)

    def test_master_key_provider_round_trip_and_binding(self):
        provider = key_provider.MasterKeyProvider(self.master)
        kek = generate_kek()
        blob = provider.protect("kek-a", kek)
        self.assertNotIn(kek, blob)
        self.assertEqual(provider.unprotect("kek-a", blob), kek)
        with self.assertRaises(key_provider.KeyProviderError):
            provider.unprotect("kek-b", blob)  # renamed file
        with self.assertRaises(key_provider.KeyProviderError):
            key_provider.MasterKeyProvider(secrets.token_bytes(32)).unprotect("kek-a", blob)
        tampered = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaises(key_provider.KeyProviderError):
            provider.unprotect("kek-a", tampered)
        with self.assertRaises(key_provider.KeyProviderError):
            provider.unprotect("kek-a", b"garbage")

    def test_kek_store_with_explicit_env_provider(self):
        provider = key_provider.MasterKeyProvider(self.master)
        kek = generate_kek()
        path = save_protected_kek(self.root, "store-test", kek, provider)
        self.assertEqual(path.suffix, ".kek")
        self.assertEqual(load_protected_kek(self.root, "store-test", provider)["kek"], kek)
        with self.assertRaises(FileExistsError):
            save_protected_kek(self.root, "store-test", generate_kek(), provider)

    def test_master_key_from_settings(self):
        encoded = base64.b64encode(self.master).decode()
        with patch.dict(os.environ, {"SECUREVAULT_KEY_PROVIDER": "env", "SECUREVAULT_MASTER_KEY": encoded}):
            self.assertEqual(key_provider.get_key_provider().name, "env")
        with patch.dict(os.environ, {"SECUREVAULT_KEY_PROVIDER": "env", "SECUREVAULT_MASTER_KEY": ""}):
            with self.assertRaises(key_provider.KeyProviderError):
                key_provider.get_key_provider()
        with patch.dict(os.environ, {"SECUREVAULT_KEY_PROVIDER": "env", "SECUREVAULT_MASTER_KEY": "bm90LWEta2V5"}):
            with self.assertRaises(key_provider.KeyProviderError):
                key_provider.get_key_provider()

    def test_provider_selection(self):
        self.assertEqual(key_provider.provider_name({}), "dpapi" if os.name == "nt" else "env")
        with self.assertRaises(key_provider.KeyProviderError):
            key_provider.provider_name({"SECUREVAULT_KEY_PROVIDER": "plaintext"})

    @unittest.skipUnless(os.name == "nt", "DPAPI is Windows-only")
    def test_dpapi_provider_binds_key_id_and_reads_legacy_files(self):
        import win32crypt

        provider = key_provider.DpapiKeyProvider()
        kek = generate_kek()
        blob = provider.protect("dpapi-a", kek)
        self.assertEqual(provider.unprotect("dpapi-a", blob), kek)
        with self.assertRaises(key_provider.KeyProviderError):
            provider.unprotect("dpapi-b", blob)
        legacy = win32crypt.CryptProtectData(kek, "SecureVault practice KEK", None, None, None, 0)
        self.assertEqual(provider.unprotect("any-id", legacy), kek)


class TestSettings(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "securevault.env"

    def test_config_file_is_read_and_environment_wins(self):
        self.config.write_text(
            "# comment\nSECUREVAULT_LOGIN_MAX_FAILURES=7\nSECUREVAULT_HSTS=1\nPATH=evil\n", encoding="utf-8")
        environ = {"SECUREVAULT_CONFIG_FILE": str(self.config), "SECUREVAULT_HSTS": "0"}
        merged = settings.environment(environ)
        self.assertEqual(merged["SECUREVAULT_LOGIN_MAX_FAILURES"], "7")
        self.assertEqual(merged["SECUREVAULT_HSTS"], "0")
        self.assertNotIn("PATH", merged)

    def test_typed_getters_validate(self):
        with patch.dict(os.environ, {"SECUREVAULT_LOGIN_MAX_FAILURES": "abc"}):
            with self.assertRaises(RuntimeError):
                settings.get_int("SECUREVAULT_LOGIN_MAX_FAILURES", 5)
        with patch.dict(os.environ, {"SECUREVAULT_HSTS": "yes"}):
            with self.assertRaises(RuntimeError):
                settings.get_bool("SECUREVAULT_HSTS", False)
        with patch.dict(os.environ, {"SECUREVAULT_CORS_ORIGINS": "*"}):
            with self.assertRaises(RuntimeError):
                settings.cors_origins()
        with patch.dict(os.environ, {"SECUREVAULT_CORS_ORIGINS": "https://a.example, http://localhost:8766"}):
            self.assertEqual(settings.cors_origins(), ["https://a.example", "http://localhost:8766"])

    def test_upload_db_path_defaults_to_main_db_and_mismatch_is_refused(self):
        main = Path(self.temp.name) / "main.db"
        merged = settings.upload_environment({"SECUREVAULT_DB_PATH": str(main),
                                              "SECUREVAULT_CONFIG_FILE": str(self.config)})
        self.assertEqual(Path(merged["SECUREVAULT_UPLOAD_DB_PATH"]), main.resolve())
        with self.assertRaises(RuntimeError):
            settings.upload_environment({"SECUREVAULT_DB_PATH": str(main),
                                         "SECUREVAULT_UPLOAD_DB_PATH": str(main) + ".other",
                                         "SECUREVAULT_CONFIG_FILE": str(self.config)})

    def test_every_documented_setting_has_a_description(self):
        for name, (default, description) in settings.SETTINGS_REFERENCE.items():
            self.assertTrue(name.startswith("SECUREVAULT_"))
            self.assertTrue(description)


if __name__ == "__main__":
    unittest.main(verbosity=2)
