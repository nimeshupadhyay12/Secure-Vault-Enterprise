"""Password hashing (Argon2id) and password policy.

Argon2id parameters are pinned here instead of relying on library defaults,
so an upgrade of argon2-cffi can never silently weaken (or change) them.

    time_cost=3, memory_cost=64 MiB, parallelism=4, hash_len=32, salt_len=16

This is RFC 9106's second recommended profile and is stronger than the
OWASP Password Storage Cheat Sheet minimum for Argon2id (m=19 MiB, t=2, p=1).
If the parameters are raised later, ``needs_rehash`` makes login transparently
upgrade stored hashes.
"""

from argon2 import PasswordHasher, Type
from argon2.exceptions import (
    VerificationError,
    InvalidHashError
)


ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 64 * 1024
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

# Passwords longer than this are rejected before hashing (cheap DoS guard).
MAX_PASSWORD_LENGTH = 1024
MIN_PASSWORD_LENGTH = 12


password_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
    type=Type.ID,
)

_dummy_hash = None


def hash_password(password: str) -> str:
    """Create an Argon2id password hash."""

    return password_hasher.hash(password)


def verify_password(
    stored_hash: str,
    password: str
) -> bool:
    """Check whether the password is correct."""

    try:
        return password_hasher.verify(
            stored_hash,
            password
        )

    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when a stored hash uses parameters other than the current ones."""

    try:
        return password_hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


def burn_dummy_verification(password: str) -> None:
    """Spend the same Argon2 work as a real check.

    Used when the username does not exist so that response time does not
    reveal which usernames are registered.
    """

    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = password_hasher.hash("securevault-timing-equaliser")
    verify_password(_dummy_hash, password)


COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "123456789012", "qwertyuiop",
    "letmein", "welcome", "iloveyou", "admin", "administrator",
    "changeme", "securevault", "passw0rd", "111111111111", "abc123456789",
    "qwerty123456", "123456123456", "football", "monkey", "dragon",
})


def password_policy_errors(password, username=None):
    """Return a list of policy violations (empty list = acceptable).

    Follows NIST SP 800-63B: length and a blocklist, no composition rules.
    """

    errors = []
    if not isinstance(password, str):
        return ["Password must be text"]
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must contain at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must contain at most {MAX_PASSWORD_LENGTH} characters")
    if password.lower() in COMMON_PASSWORDS or len(set(password)) < 4:
        errors.append("Password is too common or too repetitive")
    if username and len(username) >= 3 and username.lower() in password.lower():
        errors.append("Password must not contain the username")
    return errors
