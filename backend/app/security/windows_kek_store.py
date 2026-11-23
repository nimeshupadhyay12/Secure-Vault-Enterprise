"""Protected KEK file store.

Historically Windows-only (DPAPI). The public functions keep their names and
behaviour, but protection is now delegated to the configured key provider
(``backend.app.security.key_provider``): DPAPI on Windows by default, an
external master key elsewhere. File name: ``<key_id><provider suffix>``.
"""

import os
from pathlib import Path

from backend.app.security.kek_config import (
    validate_kek_id
)

from backend.app.security.key_provider import (
    KeyProvider,
    get_key_provider
)

from backend.app.security.key_wrapping import (
    check_key
)


MAX_PROTECTED_FILE_BYTES = 4096


def get_key_store_directory(directory):
    """
    Check an existing, trusted key-storage directory.

    This function does not create missing directories.
    """

    directory = Path(directory)

    if directory.is_symlink():
        raise ValueError(
            "Key storage directory cannot be a symbolic link"
        )

    if not directory.is_dir():
        raise FileNotFoundError(
            "Key storage directory does not exist"
        )

    return directory.resolve(strict=True)


def get_protected_key_path(directory, key_id, provider: KeyProvider | None = None):
    """
    Build a local filename using a validated key ID.

    Never accept arbitrary filenames or directory paths.
    """

    validate_kek_id(key_id)

    provider = provider or get_key_provider()

    root = get_key_store_directory(directory)

    return root / f"{key_id}{provider.file_suffix}"


def save_protected_kek(directory, key_id, kek, provider: KeyProvider | None = None):
    """
    Protect and save one KEK with the configured key provider.

    Refuses to overwrite an existing key file.
    """

    validate_kek_id(key_id)
    check_key(kek, "KEK")

    provider = provider or get_key_provider()

    file_path = get_protected_key_path(
        directory,
        key_id,
        provider
    )

    protected_bytes = provider.protect(key_id, kek)

    if len(protected_bytes) > MAX_PROTECTED_FILE_BYTES:
        raise ValueError(
            "Protected KEK exceeds expected size"
        )

    created = False

    # Exclusive creation: no accidental overwrite.
    try:
        with open(file_path, "xb") as file:
            created = True
            file.write(protected_bytes)
            file.flush()
            os.fsync(file.fileno())

    except FileExistsError:
        raise FileExistsError(
            "A protected KEK with this ID already exists"
        ) from None

    except BaseException:
        # The file has closed before cleanup.
        if created:
            try:
                file_path.unlink()
            except OSError:
                pass
        raise

    if os.name != "nt":
        os.chmod(file_path, 0o600)

    return file_path


def load_protected_kek(directory, key_id, provider: KeyProvider | None = None):
    """
    Recover a protected KEK.

    Never generates a replacement if recovery fails.
    """

    provider = provider or get_key_provider()

    file_path = get_protected_key_path(
        directory,
        key_id,
        provider
    )

    if file_path.is_symlink():
        raise ValueError(
            "Symbolic-link key files are not allowed"
        )

    with open(file_path, "rb") as file:
        protected_bytes = file.read(
            MAX_PROTECTED_FILE_BYTES + 1
        )

    if (
        not protected_bytes
        or len(protected_bytes) > MAX_PROTECTED_FILE_BYTES
    ):
        raise ValueError(
            "Invalid protected KEK file size"
        )

    kek = provider.unprotect(key_id, protected_bytes)

    check_key(kek, "Recovered KEK")

    return {
        "key_id": key_id,
        "kek": kek
    }
