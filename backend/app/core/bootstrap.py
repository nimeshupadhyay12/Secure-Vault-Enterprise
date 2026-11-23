"""One-command vault initialisation and preflight check.

``python -m backend.manage setup`` calls :func:`run_setup`:

1. Chooses locations (already-configured values win; otherwise ``runtime/``).
2. Creates the data, ciphertext and key directories and restricts them to the
   current account (protected DACL on Windows, 0700 elsewhere).
3. Creates/migrates the main database (users, documents, migrations 001-004,
   key table, refresh tokens, revocation, lockout, audit log), the
   organisation sidecar database and the binary-vault database.
4. Creates the KEK once and protects it with the key provider (DPAPI by
   default on Windows). An existing KEK is verified, never replaced.
5. Writes ``runtime/securevault.env`` (random JWT secret and audit HMAC key,
   paths, process identity) without overwriting values that already exist.
6. Runs :func:`run_check`, the same preflight chain the API runs at startup.

Everything is idempotent: running setup again changes nothing that exists.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI

from backend.app.core import settings


DEFAULT_KEY_ID = "securevault-kek-1"


class SetupError(Exception):
    """Setup cannot continue; the message says what to do."""


def _pick(current, name, default):
    value = current.get(name)
    return value if value else str(default)


def _legacy_or(default_path: Path, legacy_name: str) -> Path:
    """Keep using a database from the old hard-coded location if present."""

    legacy = settings.DEFAULT_DATA_DIR / legacy_name
    return legacy if legacy.is_file() else default_path


def plan_values(runtime: Path, current: dict, key_id=None, provider=None) -> dict:
    from backend.app.security import key_provider

    data = runtime / "data"
    values = {
        "SECUREVAULT_DB_PATH": _pick(current, "SECUREVAULT_DB_PATH",
                                     _legacy_or(data / "securevault.db", "securevault.db")),
        "SECUREVAULT_ORG_DB_PATH": _pick(current, "SECUREVAULT_ORG_DB_PATH",
                                         _legacy_or(data / "vault_organization.db", "vault_organization.db")),
        "SECUREVAULT_BINARY_DB_PATH": _pick(current, "SECUREVAULT_BINARY_DB_PATH",
                                            _legacy_or(data / "vault_binary.db", "vault_binary.db")),
        "SECUREVAULT_BINARY_STORAGE_DIR": _pick(current, "SECUREVAULT_BINARY_STORAGE_DIR", runtime / "binary-files"),
        "SECUREVAULT_UPLOAD_STORAGE_DIR": _pick(current, "SECUREVAULT_UPLOAD_STORAGE_DIR", runtime / "encrypted-files"),
        "SECUREVAULT_UPLOAD_KEK_DIR": _pick(current, "SECUREVAULT_UPLOAD_KEK_DIR", runtime / "protected-keys"),
        "SECUREVAULT_UPLOAD_KEK_ID": key_id or _pick(current, "SECUREVAULT_UPLOAD_KEK_ID", DEFAULT_KEY_ID),
        "SECUREVAULT_KEY_PROVIDER": provider or key_provider.provider_name(current),
        "SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD": "1",
        "SECUREVAULT_JWT_SECRET": _pick(current, "SECUREVAULT_JWT_SECRET", secrets.token_urlsafe(48)),
        "SECUREVAULT_AUDIT_KEY": _pick(current, "SECUREVAULT_AUDIT_KEY", secrets.token_urlsafe(48)),
    }
    for name in ("SECUREVAULT_DB_PATH", "SECUREVAULT_ORG_DB_PATH", "SECUREVAULT_BINARY_DB_PATH",
                 "SECUREVAULT_BINARY_STORAGE_DIR", "SECUREVAULT_UPLOAD_STORAGE_DIR",
                 "SECUREVAULT_UPLOAD_KEK_DIR"):
        values[name] = str(Path(values[name]).resolve())
    if os.name == "nt":
        from backend.app.security.encrypted_upload_identity_guard import read_current_process_sid
        values["SECUREVAULT_UPLOAD_WINDOWS_SID"] = read_current_process_sid()
    else:
        values["SECUREVAULT_UPLOAD_EXPECTED_UID"] = str(os.geteuid())
    return values


def _provider_for(values, current, dev_master_key, notes):
    from backend.app.security import key_provider
    from backend.app.security.kek_config import decode_kek
    import base64

    if values["SECUREVAULT_KEY_PROVIDER"] == "dpapi":
        if os.name != "nt":
            raise SetupError("The 'dpapi' key provider requires Windows; use SECUREVAULT_KEY_PROVIDER=env")
        return key_provider.DpapiKeyProvider()
    if values["SECUREVAULT_KEY_PROVIDER"] != "env":
        raise SetupError("SECUREVAULT_KEY_PROVIDER must be 'dpapi' or 'env'")

    encoded = current.get("SECUREVAULT_MASTER_KEY")
    if not encoded:
        if not dev_master_key:
            raise SetupError(
                "The 'env' key provider needs SECUREVAULT_MASTER_KEY (base64, 32 bytes), "
                "kept outside the vault directory (secret manager / service environment). "
                "Generate one with: python -c \"import base64,secrets;"
                "print(base64.b64encode(secrets.token_bytes(32)).decode())\" "
                "or re-run with --dev-master-key to store one in the config file (development only)."
            )
        encoded = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        values["SECUREVAULT_MASTER_KEY"] = encoded
        notes.append("WARNING: master key written to the config file (development only).")
    try:
        return key_provider.MasterKeyProvider(decode_kek(encoded))
    except (ValueError, key_provider.KeyProviderError) as error:
        raise SetupError(f"SECUREVAULT_MASTER_KEY is invalid: {error}") from None


def _initialise_main_database(db_path: Path):
    from backend.app.database.db import initialize_database
    from backend.app.database.owned_document_repository import initialize_owned_documents
    from backend.app.database.migrations import migration_001, migration_002, migration_003, migration_004

    db_path.parent.mkdir(parents=True, exist_ok=True)
    initialize_database(db_path)
    initialize_owned_documents(db_path)
    return [
        migration_001.run_migration(db_path),
        migration_002.run_migration(db_path),
        migration_003.apply_migration_003(db_path),
        migration_004.apply_migration_004(db_path),
    ]


def _initialise_sidecars(values):
    from backend.app.api.vault_binary import initialize_binary_database
    from backend.app.api.vault_organizer import initialize_sidecar

    org = Path(values["SECUREVAULT_ORG_DB_PATH"])
    org.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(org)):
        pass
    initialize_sidecar(org)
    initialize_binary_database(Path(values["SECUREVAULT_BINARY_DB_PATH"]))


def _write_config(config_path: Path, values: dict):
    from backend.app.security.fs_permissions import restrict_to_owner

    existing = settings._read_config_file(config_path) if config_path.is_file() else {}
    merged = {**values, **existing}  # never overwrite an existing value
    config_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SecureVault configuration written by `python -m backend.manage setup`.",
        "# Contains secrets: keep it out of version control (runtime/ is gitignored).",
        "# Environment variables override anything in this file.",
    ]
    lines += [f"{name}={merged[name]}" for name in sorted(merged)]
    temporary = config_path.with_name(config_path.name + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(temporary, config_path)
    restrict_to_owner(config_path)
    return merged


def run_setup(runtime_dir=None, key_id=None, provider=None, dev_master_key=False, report=print) -> dict:
    from backend.app.security import audit_log
    from backend.app.security.fs_permissions import restrict_to_owner
    from backend.app.security.key_wrapping import generate_kek
    from backend.app.security.windows_kek_store import (
        get_protected_key_path, load_protected_kek, save_protected_kek,
    )

    runtime = Path(runtime_dir).resolve() if runtime_dir else (settings.REPO_ROOT / "runtime")
    config_path = settings.config_file_path() if not runtime_dir or os.environ.get(
        "SECUREVAULT_CONFIG_FILE") else runtime / "securevault.env"
    current = settings.environment({**os.environ, "SECUREVAULT_CONFIG_FILE": str(config_path)})

    notes = []
    values = plan_values(runtime, current, key_id=key_id, provider=provider)
    provider_impl = _provider_for(values, current, dev_master_key, notes)

    # 1. Directories (restricted to this account).
    for name in ("SECUREVAULT_UPLOAD_STORAGE_DIR", "SECUREVAULT_UPLOAD_KEK_DIR", "SECUREVAULT_BINARY_STORAGE_DIR"):
        directory = Path(values[name])
        directory.mkdir(parents=True, exist_ok=True)
        restrict_to_owner(directory)
    for name in ("SECUREVAULT_DB_PATH", "SECUREVAULT_ORG_DB_PATH", "SECUREVAULT_BINARY_DB_PATH"):
        Path(values[name]).parent.mkdir(parents=True, exist_ok=True)

    # 2. Databases and migrations.
    migrations = _initialise_main_database(Path(values["SECUREVAULT_DB_PATH"]))
    _initialise_sidecars(values)

    # 3. KEK: create once, otherwise verify.
    key_dir, kid = Path(values["SECUREVAULT_UPLOAD_KEK_DIR"]), values["SECUREVAULT_UPLOAD_KEK_ID"]
    key_file = get_protected_key_path(key_dir, kid, provider_impl)
    if key_file.exists():
        load_protected_kek(key_dir, kid, provider_impl)
        kek_status = f"existing KEK verified ({key_file.name})"
    else:
        save_protected_kek(key_dir, kid, generate_kek(), provider_impl)
        kek_status = f"new KEK created and protected with {provider_impl.name} ({key_file.name})"
        audit_log.record_event("kek_created", detail={"key_id": kid, "provider": provider_impl.name},
                               db_path=values["SECUREVAULT_DB_PATH"])

    # 4. Config file.
    merged = _write_config(config_path, values)

    # Run the preflight exactly as the server would see this config file.
    previous = os.environ.get("SECUREVAULT_CONFIG_FILE")
    os.environ["SECUREVAULT_CONFIG_FILE"] = str(config_path)
    try:
        ok, message = run_check()
    finally:
        if previous is None:
            os.environ.pop("SECUREVAULT_CONFIG_FILE", None)
        else:
            os.environ["SECUREVAULT_CONFIG_FILE"] = previous

    report(f"Config file : {config_path}")
    report(f"Database    : {merged['SECUREVAULT_DB_PATH']} (migrations: {', '.join(migrations)})")
    report(f"Key store   : {kek_status}")
    for note in notes:
        report(note)
    if config_path != settings.DEFAULT_CONFIG_FILE and not os.environ.get("SECUREVAULT_CONFIG_FILE"):
        report(f"Set SECUREVAULT_CONFIG_FILE={config_path} before starting the API.")
    report(("PREFLIGHT OK: " if ok else "PREFLIGHT FAILED: ") + message)
    if not ok:
        raise SetupError(message)
    return {"config_path": config_path, "values": merged, "kek": kek_status}


def run_check(environ=None):
    """Run the startup preflight without starting the server. Returns (ok, message)."""

    from backend.app.security.encrypted_upload_key_file_guard import (
        activate_encrypted_upload_with_key_file_guard,
    )

    try:
        env = settings.upload_environment(environ)
        secret = env.get("SECUREVAULT_JWT_SECRET") or ""
        development = (env.get("SECUREVAULT_ENV") or "").lower() == "development"
        if len(secret) < 32 and not development:
            return False, "SECUREVAULT_JWT_SECRET must contain at least 32 characters"
        if env.get("SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD", "0") != "1":
            return False, "SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD is not '1' (encrypted storage stays disabled)"
        result = activate_encrypted_upload_with_key_file_guard(FastAPI(), env)
    except Exception as error:
        return False, str(error)
    if result.get("registered") is not True:
        return False, "Encrypted upload was not registered"
    return True, "key file ACL, directory ACLs, process identity, paths, schema and key recovery verified"
