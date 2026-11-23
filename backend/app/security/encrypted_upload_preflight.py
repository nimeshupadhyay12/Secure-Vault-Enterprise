

from backend.app.security import document_types


# Default per-document limit (5 MiB). The effective limit is
# SECUREVAULT_MAX_DOCUMENT_BYTES, see max_upload_bytes().
MAX_PRACTICE_UPLOAD_BYTES = document_types.DEFAULT_MAX_DOCUMENT_BYTES


def max_upload_bytes():
    """Effective per-document size limit from configuration."""

    return document_types.max_document_bytes()

# Shared allow-list (report.txt, scan.pdf, budget.xlsx, ...).
SAFE_FILENAME = document_types.SAFE_FILENAME

# Windows reserves these device names,
# including when followed by an extension.
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3",
    "LPT4", "LPT5", "LPT6", "LPT7",
    "LPT8", "LPT9"
}


class EncryptedUploadPreflightError(ValueError):
    """Incoming practice upload is not acceptable."""


def _validate_positive_id(value):
    """
    Require a positive integer.

    Reject booleans even though Python treats
    bool as a subclass of int.
    """
    return type(value) is int and value > 0


def _validate_filename(filename):
    """
    Accept only conservative, simple names with an
    allowed document extension (see document_types).

    Do not accept folder paths or special
    Windows device names.
    """

    try:
        document_types.validate_filename(filename)
    except ValueError:
        raise EncryptedUploadPreflightError(
            "Invalid upload metadata"
        ) from None

    return filename


def prepare_encrypted_upload(
    filename,
    content,
    owner_user_id,
    document_id,
    max_bytes=None
):
    """
    Validate input for a future encrypted upload.

    Does NOT:
      - save plaintext
      - create files
      - encrypt data
      - create or load keys
      - connect to SQLite
      - authenticate the owner

    Returns only a safe metadata summary.
    """

    try:
        if not _validate_positive_id(owner_user_id):
            raise ValueError("Invalid owner ID")

        if not _validate_positive_id(document_id):
            raise ValueError("Invalid document ID")

        configured_limit = max_upload_bytes()

        if max_bytes is None:
            max_bytes = configured_limit

        if (
            type(max_bytes) is not int
            or not 1 <= max_bytes <= configured_limit
        ):
            raise ValueError("Invalid size limit")

        safe_name = _validate_filename(filename)

        # Only immutable byte strings are accepted.
        # The API will need to bound reads before
        # constructing this in-memory value.
        if type(content) is not bytes:
            raise ValueError("Content must be bytes")

        content_size = len(content)

        if not 1 <= content_size <= max_bytes:
            raise ValueError("Invalid content size")

        # Structural check for the declared type
        # (UTF-8 text, PDF, DOCX, XLSX, PNG, JPEG).
        media_type = document_types.check_content(
            safe_name, content
        )

        # Intentionally do not return the content.
        return {
            "ready": True,
            "filename": safe_name,
            "size_bytes": content_size,
            "media_type": media_type,
            "owner_user_id": owner_user_id,
            "document_id": document_id,
            "encryption_required": True,
            "plaintext_persisted": False
        }

    except (ValueError, TypeError):
        raise EncryptedUploadPreflightError(
            "Encrypted upload preflight failed"
        ) from None
