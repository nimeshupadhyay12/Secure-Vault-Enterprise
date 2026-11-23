"""SHA-256 integrity checks for decrypted documents.

AES-256-GCM already authenticates every ciphertext (any modified byte makes
decryption fail). The SHA-256 fingerprint recorded at upload time adds an
independent end-to-end check: the bytes handed back to the owner must be
exactly the bytes that were uploaded, even if a key, the storage layer or the
code that glues them together is wrong. Comparison is constant-time
(``hmac.compare_digest``).
"""

import hashlib
import hmac
import re


SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class IntegrityVerificationError(Exception):
    """Decrypted content does not match its recorded SHA-256 fingerprint."""


def sha256_hex(data: bytes) -> str:
    if type(data) is not bytes:
        raise TypeError("Data must be bytes")
    return hashlib.sha256(data).hexdigest()


def validate_sha256_hex(value) -> str:
    if not isinstance(value, str) or SHA256_HEX.fullmatch(value) is None:
        raise ValueError("SHA-256 fingerprint must be 64 lowercase hex characters")
    return value


def verify_sha256(data: bytes, expected_hex: str) -> str:
    """Raise IntegrityVerificationError unless sha256(data) == expected_hex."""

    actual = sha256_hex(data)
    if not isinstance(expected_hex, str) or not hmac.compare_digest(
        actual.encode("ascii"), expected_hex.lower().encode("ascii", "replace")
    ):
        raise IntegrityVerificationError("SHA-256 verification failed")
    return actual
