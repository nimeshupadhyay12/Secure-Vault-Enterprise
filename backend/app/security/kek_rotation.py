"""KEK rotation: re-wrap every data key under a new KEK, files untouched.

Envelope encryption makes rotation cheap: each document's ciphertext is
encrypted with its own DEK, and only the 48-byte wrapped DEK depends on the
KEK. Rotation therefore

1. creates (or, on a re-run, loads) the new KEK with the key provider,
2. for every row in ``encrypted_document_keys``: unwraps the DEK with the
   KEK named in that row, re-wraps it with the new KEK and a fresh nonce
   under the same authenticated context, and records the new key id -
   all inside one SQLite transaction,
3. does the same for the binary vault (``binary_documents`` always uses the
   active KEK, so already-rotated rows are recognised and skipped),
4. returns counts; the caller then switches SECUREVAULT_UPLOAD_KEK_ID.

No ``.svenc``/``.svbin`` file is read or written. The old KEK file is kept so
backups taken before the rotation stay recoverable; delete it only after
confirming you no longer need those backups. Stop the API while rotating.
"""

from __future__ import annotations

import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.security.kek_config import validate_kek_id
from backend.app.security.key_wrapping import generate_kek
from backend.app.security.practice_document_service import _aad as document_aad
from backend.app.security.windows_kek_store import (
    get_protected_key_path,
    load_protected_kek,
    save_protected_kek,
)


class KekRotationError(Exception):
    """Rotation stopped; nothing in the failing database was changed."""


def _load_or_create(key_dir, key_id, provider=None):
    path = get_protected_key_path(key_dir, key_id, provider)
    if path.exists():
        return load_protected_kek(key_dir, key_id, provider)["kek"], False
    kek = generate_kek()
    save_protected_kek(key_dir, key_id, kek, provider)
    return kek, True


def rotate_document_keys(db_path, key_dir, new_key_id, new_kek, provider=None):
    """Re-wrap all text-path DEKs. Returns the number of rows re-wrapped."""

    cache = {new_key_id: new_kek}
    rewrapped = 0
    with closing(sqlite3.connect(db_path, timeout=30)) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            rows = db.execute(
                """SELECT k.document_id, k.storage_id, k.key_id, k.wrap_nonce, k.wrapped_dek,
                          d.owner_user_id, d.filename
                   FROM encrypted_document_keys AS k
                   JOIN owned_documents AS d ON d.id = k.document_id"""
            ).fetchall()
            for document_id, storage_id, key_id, nonce, wrapped, owner, filename in rows:
                if key_id == new_key_id:
                    continue
                if key_id not in cache:
                    cache[key_id] = load_protected_kek(key_dir, key_id, provider)["kek"]
                context = document_aad("key", owner, document_id, storage_id, filename)
                try:
                    dek = AESGCM(cache[key_id]).decrypt(nonce, wrapped, context)
                except InvalidTag:
                    raise KekRotationError(f"document {document_id}: wrapped key failed authentication") from None
                new_nonce = secrets.token_bytes(12)
                new_wrapped = AESGCM(new_kek).encrypt(new_nonce, dek, context)
                db.execute(
                    "UPDATE encrypted_document_keys SET key_id = ?, wrap_nonce = ?, wrapped_dek = ? "
                    "WHERE document_id = ?",
                    (new_key_id, new_nonce, new_wrapped, document_id),
                )
                rewrapped += 1
            db.commit()
        except Exception:
            db.rollback()
            raise
    return rewrapped


def rotate_binary_keys(binary_db, old_kek, new_kek):
    """Re-wrap binary-vault DEKs (rows already under new_kek are skipped)."""

    from backend.app.api.vault_binary import _aad as binary_aad

    path = Path(binary_db)
    if not path.is_file():
        return 0
    rewrapped = 0
    with closing(sqlite3.connect(path, timeout=30)) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            rows = db.execute(
                "SELECT id, owner_id, storage_id, filename, wrap_nonce, wrapped_dek "
                "FROM binary_documents WHERE status = 'ready'"
            ).fetchall()
            for file_id, owner, storage_id, filename, nonce, wrapped in rows:
                context = binary_aad(owner, file_id, storage_id, filename) + b"|key"
                try:
                    dek = AESGCM(old_kek).decrypt(nonce, wrapped, context)
                except InvalidTag:
                    try:
                        AESGCM(new_kek).decrypt(nonce, wrapped, context)
                        continue  # already rotated by an earlier run
                    except InvalidTag:
                        raise KekRotationError(f"binary document {file_id}: wrapped key failed authentication") from None
                new_nonce = secrets.token_bytes(12)
                db.execute(
                    "UPDATE binary_documents SET wrap_nonce = ?, wrapped_dek = ? WHERE id = ?",
                    (new_nonce, AESGCM(new_kek).encrypt(new_nonce, dek, context), file_id),
                )
                rewrapped += 1
            db.commit()
        except Exception:
            db.rollback()
            raise
    return rewrapped


def rotate_kek(*, db_path, binary_db, key_dir, old_key_id, new_key_id, provider=None):
    validate_kek_id(old_key_id)
    validate_kek_id(new_key_id)
    if old_key_id == new_key_id:
        raise KekRotationError("The new key id must differ from the active key id")
    old_kek = load_protected_kek(key_dir, old_key_id, provider)["kek"]
    new_kek, created = _load_or_create(key_dir, new_key_id, provider)
    documents = rotate_document_keys(db_path, key_dir, new_key_id, new_kek, provider)
    binaries = rotate_binary_keys(binary_db, old_kek, new_kek)
    return {"new_kek_created": created, "documents_rewrapped": documents, "binary_rewrapped": binaries}
