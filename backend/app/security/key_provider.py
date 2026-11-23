"""Pluggable protection for key-encryption keys (KEKs) at rest.

A KEK never touches disk in the clear. A *key provider* turns the 32-byte KEK
into an opaque protected blob and back:

``dpapi`` (default on Windows)
    Windows DPAPI, current-user scope. New files are bound to their key id
    through DPAPI's optional entropy, so renaming ``a.dpapi`` to ``b.dpapi``
    does not produce a usable key. Files written by older versions (no
    entropy) are still readable.

``env`` (default elsewhere; used by Linux/macOS and CI)
    AES-256-GCM under a master key supplied in ``SECUREVAULT_MASTER_KEY``
    (base64, 32 bytes). Blob = ``b"SVK1" || nonce(12) || ciphertext+tag``,
    AAD = ``securevault-kek-v1:<key_id>``. The master key must come from a
    secret store / environment, never from the same disk as the key files.
"""

from __future__ import annotations

import os
import secrets
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.core import settings
from backend.app.security.kek_config import decode_kek, validate_kek_id


KEY_SIZE = 32


class KeyProviderError(Exception):
    """A KEK could not be protected or recovered."""


class KeyProvider(ABC):
    name: str
    file_suffix: str

    @abstractmethod
    def protect(self, key_id: str, kek: bytes) -> bytes:
        """Return an opaque protected blob for ``kek``."""

    @abstractmethod
    def unprotect(self, key_id: str, blob: bytes) -> bytes:
        """Recover the KEK from ``blob`` or raise KeyProviderError."""


def _check_kek(kek):
    if type(kek) is not bytes or len(kek) != KEY_SIZE:
        raise KeyProviderError("KEK must contain 32 bytes")


class DpapiKeyProvider(KeyProvider):
    name = "dpapi"
    file_suffix = ".dpapi"
    DESCRIPTION = "SecureVault KEK"
    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    @staticmethod
    def _entropy(key_id: str) -> bytes:
        return ("SecureVault-KEK-v2:" + key_id).encode("utf-8")

    def protect(self, key_id, kek):
        validate_kek_id(key_id)
        _check_kek(kek)
        import win32crypt

        return win32crypt.CryptProtectData(
            kek, self.DESCRIPTION, self._entropy(key_id), None, None,
            self.CRYPTPROTECT_UI_FORBIDDEN,
        )

    def unprotect(self, key_id, blob):
        validate_kek_id(key_id)
        import pywintypes
        import win32crypt

        last_error = None
        # Key-id-bound files first, then legacy files written without entropy.
        for entropy in (self._entropy(key_id), None):
            try:
                _description, kek = win32crypt.CryptUnprotectData(
                    blob, entropy, None, None, self.CRYPTPROTECT_UI_FORBIDDEN
                )
            except pywintypes.error as error:
                last_error = error
                continue
            _check_kek(kek)
            return kek
        raise KeyProviderError("DPAPI could not recover the KEK") from last_error


class MasterKeyProvider(KeyProvider):
    """AES-256-GCM wrapping under an externally supplied master key."""

    name = "env"
    file_suffix = ".kek"
    MAGIC = b"SVK1"

    def __init__(self, master_key: bytes):
        _check_kek(master_key)
        self._aead = AESGCM(master_key)

    @classmethod
    def from_settings(cls):
        encoded = settings.get("SECUREVAULT_MASTER_KEY")
        if not encoded:
            raise KeyProviderError(
                "SECUREVAULT_MASTER_KEY is required for the 'env' key provider"
            )
        try:
            return cls(decode_kek(encoded))
        except ValueError as error:
            raise KeyProviderError(f"SECUREVAULT_MASTER_KEY invalid: {error}") from None

    @staticmethod
    def _aad(key_id):
        return ("securevault-kek-v1:" + key_id).encode("utf-8")

    def protect(self, key_id, kek):
        validate_kek_id(key_id)
        _check_kek(kek)
        nonce = secrets.token_bytes(12)
        return self.MAGIC + nonce + self._aead.encrypt(nonce, kek, self._aad(key_id))

    def unprotect(self, key_id, blob):
        validate_kek_id(key_id)
        if type(blob) is not bytes or len(blob) != 4 + 12 + KEY_SIZE + 16 or not blob.startswith(self.MAGIC):
            raise KeyProviderError("Unrecognised protected KEK format")
        try:
            kek = self._aead.decrypt(blob[4:16], blob[16:], self._aad(key_id))
        except InvalidTag:
            raise KeyProviderError("Master key or key id does not match this KEK") from None
        _check_kek(kek)
        return kek


def provider_name(environ=None) -> str:
    if environ is not None:
        name = environ.get("SECUREVAULT_KEY_PROVIDER") or ""
    else:
        name = settings.get("SECUREVAULT_KEY_PROVIDER", "") or ""
    if not name:
        name = "dpapi" if os.name == "nt" else "env"
    if name not in ("dpapi", "env"):
        raise KeyProviderError("SECUREVAULT_KEY_PROVIDER must be 'dpapi' or 'env'")
    return name


def get_key_provider() -> KeyProvider:
    name = provider_name()
    if name == "dpapi":
        if os.name != "nt":
            raise KeyProviderError("The 'dpapi' key provider requires Windows")
        return DpapiKeyProvider()
    return MasterKeyProvider.from_settings()
