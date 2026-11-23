"""Accepted document types for the encrypted vault.

One allow-list, used by every upload path:

=========  ==========================================================  ======
Extension  Check                                                       Media
=========  ==========================================================  ======
.txt       valid UTF-8, no NUL bytes                                   text/plain
.pdf       ``%PDF-`` header and ``%%EOF`` trailer                       application/pdf
.docx      ZIP with ``[Content_Types].xml`` + ``word/document.xml``     OOXML
.xlsx      ZIP with ``[Content_Types].xml`` + ``xl/workbook.xml``       OOXML
.png       PNG signature + IHDR chunk                                  image/png
.jpg/.jpeg SOI/EOI markers                                             image/jpeg
=========  ==========================================================  ======

ZIP containers are bounded (entry count, decompressed size, compression
ratio, no absolute/parent paths, no encrypted members) to resist zip bombs.
These are structural checks that keep the vault to the declared formats;
they are *not* malware scanning. Downloads are always served as
``application/octet-stream`` with ``Content-Disposition: attachment`` so the
browser never renders uploaded content inline.
"""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import PurePath

from backend.app.core import settings


DEFAULT_MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
HARD_MAX_DOCUMENT_BYTES = 50 * 1024 * 1024

MEDIA_TYPES = {
    ".txt": "text/plain",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}

SAFE_FILENAME = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.(?:txt|pdf|docx|xlsx|png|jpg|jpeg)",
    re.IGNORECASE,
)

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

MAX_ZIP_ENTRIES = 512
MAX_ZIP_TOTAL_BYTES = 24 * 1024 * 1024
MAX_ZIP_RATIO = 100


class DocumentTypeError(ValueError):
    """The upload is not an accepted, well-formed document."""


def max_document_bytes() -> int:
    """Configured per-document limit (SECUREVAULT_MAX_DOCUMENT_BYTES)."""

    value = settings.get_int("SECUREVAULT_MAX_DOCUMENT_BYTES", DEFAULT_MAX_DOCUMENT_BYTES, minimum=1)
    if value > HARD_MAX_DOCUMENT_BYTES:
        raise RuntimeError("SECUREVAULT_MAX_DOCUMENT_BYTES may not exceed 50 MiB")
    return value


def validate_filename(filename) -> str:
    if type(filename) is not str or not 5 <= len(filename) <= 105:
        raise DocumentTypeError("Filename must contain 5 to 105 characters")
    if SAFE_FILENAME.fullmatch(filename) is None or ".." in filename:
        raise DocumentTypeError(
            "Use a simple name ending in .txt, .pdf, .docx, .xlsx, .png, .jpg or .jpeg"
        )
    if filename.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
        raise DocumentTypeError("Reserved device name is not allowed")
    return filename


def extension(filename) -> str:
    return PurePath(filename).suffix.lower()


def _safe_member(name):
    return (not name.startswith("/") and "\\" not in name
            and all(part not in ("", "..") for part in name.split("/")))


def _check_ooxml(data, required_part):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ZIP_ENTRIES:
                raise DocumentTypeError("Too many archive entries")
            total = 0
            names = set()
            for member in members:
                if not _safe_member(member.filename):
                    raise DocumentTypeError("Unsafe archive path")
                if member.flag_bits & 0x1:
                    raise DocumentTypeError("Encrypted Office documents are refused")
                total += member.file_size
                if total > MAX_ZIP_TOTAL_BYTES:
                    raise DocumentTypeError("Office document decompresses too large")
                if member.file_size > 2 * 1024 * 1024 and \
                        member.file_size > max(member.compress_size, 1) * MAX_ZIP_RATIO:
                    raise DocumentTypeError("Suspicious compression ratio")
                names.add(member.filename)
    except (zipfile.BadZipFile, EOFError, OSError):
        raise DocumentTypeError("Invalid Office Open XML document") from None
    if not {"[Content_Types].xml", required_part}.issubset(names):
        raise DocumentTypeError("Missing expected Office document parts")


def check_content(filename, data) -> str:
    """Structural check of ``data`` for the type implied by ``filename``."""

    ext = extension(filename)
    if ext == ".txt":
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise DocumentTypeError("Text files must be valid UTF-8") from None
        if b"\x00" in data:
            raise DocumentTypeError("NUL characters are not allowed in text files")
    elif ext == ".pdf":
        if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
            raise DocumentTypeError("PDF header/trailer validation failed")
    elif ext == ".png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) < 33 or data[12:16] != b"IHDR":
            raise DocumentTypeError("PNG structure validation failed")
    elif ext in (".jpg", ".jpeg"):
        if not (len(data) >= 4 and data[:2] == b"\xff\xd8" and data[-2:] == b"\xff\xd9"):
            raise DocumentTypeError("JPEG structure validation failed")
    elif ext == ".docx":
        _check_ooxml(data, "word/document.xml")
    elif ext == ".xlsx":
        _check_ooxml(data, "xl/workbook.xml")
    else:
        raise DocumentTypeError("Unsupported document type")
    return MEDIA_TYPES[ext]


def validate_document(filename, data, max_bytes=None) -> str:
    """Validate name, size and structure. Returns the media type."""

    validate_filename(filename)
    limit = max_document_bytes() if max_bytes is None else max_bytes
    if type(data) is not bytes or not 1 <= len(data) <= limit:
        raise DocumentTypeError(f"Document must contain 1 byte to {limit} bytes")
    return check_content(filename, data)
