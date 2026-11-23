"""Central SecureVault configuration.

Every setting the application reads lives here, so there is exactly one
place that decides where the database is, which key provider is used and
which security limits apply.

Values are resolved in this order (first match wins):

1. Process environment variables (``SECUREVAULT_*``).
2. An optional ``KEY=VALUE`` config file. The path comes from
   ``SECUREVAULT_CONFIG_FILE``; otherwise ``<repo>/runtime/securevault.env``
   is used when it exists. ``python -m backend.manage setup`` writes it.
3. Built-in defaults.

The config file is gitignored (``runtime/``). It never needs to be committed.
"""

from __future__ import annotations

import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = REPO_ROOT / "backend"
DEFAULT_DATA_DIR = BACKEND_DIR / "data"
DEFAULT_CONFIG_FILE = REPO_ROOT / "runtime" / "securevault.env"


# name -> (default, description). The README "Configuration" table mirrors this.
SETTINGS_REFERENCE = {
    "SECUREVAULT_ENV": (
        "production",
        "'development' allows an ephemeral JWT secret; anything else is production.",
    ),
    "SECUREVAULT_CONFIG_FILE": (
        str(DEFAULT_CONFIG_FILE),
        "Optional KEY=VALUE file read after the environment.",
    ),
    "SECUREVAULT_DB_PATH": (
        str(DEFAULT_DATA_DIR / "securevault.db"),
        "Main SQLite database (users, documents, keys, tokens, audit log).",
    ),
    "SECUREVAULT_ORG_DB_PATH": (
        str(DEFAULT_DATA_DIR / "vault_organization.db"),
        "Folder/tag/favourite sidecar database.",
    ),
    "SECUREVAULT_BINARY_DB_PATH": (
        str(DEFAULT_DATA_DIR / "vault_binary.db"),
        "Binary-document (PDF/DOCX/XLSX/PNG/JPEG) metadata database.",
    ),
    "SECUREVAULT_BINARY_STORAGE_DIR": (
        str(REPO_ROOT.parent / "binary-files"),
        "Ciphertext directory for binary documents (*.svbin).",
    ),
    "SECUREVAULT_JWT_SECRET": (
        "",
        "HS256 signing secret, at least 32 characters. Required.",
    ),
    "SECUREVAULT_KEY_PROVIDER": (
        "dpapi on Windows, env elsewhere",
        "How KEK files are protected: 'dpapi' or 'env'.",
    ),
    "SECUREVAULT_MASTER_KEY": (
        "",
        "Base64 32-byte master key for the 'env' key provider.",
    ),
    "SECUREVAULT_AUDIT_KEY": (
        "",
        "Optional HMAC key (32+ chars) for the tamper-evident audit chain.",
    ),
    "SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD": (
        "0",
        "'1' registers encrypted upload/download after preflight checks.",
    ),
    "SECUREVAULT_UPLOAD_DB_PATH": (
        "",
        "Must point to the same file as SECUREVAULT_DB_PATH when enabled.",
    ),
    "SECUREVAULT_UPLOAD_STORAGE_DIR": (
        "",
        "Existing ciphertext directory for text documents (*.svenc).",
    ),
    "SECUREVAULT_UPLOAD_KEK_DIR": (
        "",
        "Existing directory holding protected KEK files.",
    ),
    "SECUREVAULT_UPLOAD_KEK_ID": (
        "",
        "Active KEK identifier used to wrap new data keys.",
    ),
    "SECUREVAULT_UPLOAD_WINDOWS_SID": (
        "",
        "Windows only: SID the server process must run as (enabled mode).",
    ),
    "SECUREVAULT_UPLOAD_EXPECTED_UID": (
        "",
        "Linux/macOS only: uid the server process must run as (enabled mode).",
    ),
    "SECUREVAULT_LOGIN_MAX_FAILURES": (
        "5",
        "Failed logins allowed per username inside the window before lockout.",
    ),
    "SECUREVAULT_LOGIN_WINDOW_SECONDS": (
        "900",
        "Window in which failed logins are counted.",
    ),
    "SECUREVAULT_LOGIN_LOCKOUT_SECONDS": (
        "900",
        "How long a username stays locked after too many failures.",
    ),
    "SECUREVAULT_MAX_DOCUMENT_BYTES": (
        str(5 * 1024 * 1024),
        "Largest accepted document (bytes, max 50 MiB) for /documents/encrypted.",
    ),
    "SECUREVAULT_MAX_REQUEST_BYTES": (
        str(6 * 1024 * 1024),
        "Hard cap on any request body (checked before handlers run).",
    ),
    "SECUREVAULT_CORS_ORIGINS": (
        "",
        "Comma-separated exact origins allowed by CORS. Empty = same-origin only.",
    ),
    "SECUREVAULT_HSTS": (
        "0",
        "'1' adds Strict-Transport-Security (only behind HTTPS).",
    ),
    "SECUREVAULT_ENABLE_DOCS": (
        "1",
        "'0' hides /docs, /redoc and /openapi.json.",
    ),
}


def _read_config_file(path: Path) -> dict:
    values = {}
    try:
        if not path.is_file() or path.is_symlink():
            return values
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            name = name.strip()
            if name.startswith("SECUREVAULT_"):
                values[name] = value.strip()
    except OSError:
        return {}
    return values


def config_file_path(environ=None) -> Path:
    environ = os.environ if environ is None else environ
    configured = environ.get("SECUREVAULT_CONFIG_FILE")
    return Path(configured) if configured else DEFAULT_CONFIG_FILE


def environment(environ=None) -> dict:
    """Return a merged mapping: config file values overlaid by the environment."""

    environ = os.environ if environ is None else environ
    merged = _read_config_file(config_file_path(environ))
    merged.update(
        {k: v for k, v in environ.items() if k.startswith("SECUREVAULT_")}
    )
    return merged


def get(name: str, default: str | None = None) -> str | None:
    value = environment().get(name)
    if value is None or value == "":
        return default
    return value


def get_int(name: str, default: int, minimum: int = 0) -> int:
    raw = get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer") from None
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")
    return value


def get_bool(name: str, default: bool) -> bool:
    raw = get(name)
    if raw is None:
        return default
    if raw not in ("0", "1"):
        raise RuntimeError(f"{name} must be '0' or '1'")
    return raw == "1"


def db_path() -> Path:
    return Path(get("SECUREVAULT_DB_PATH", SETTINGS_REFERENCE["SECUREVAULT_DB_PATH"][0]))


def org_db_path() -> Path:
    return Path(get("SECUREVAULT_ORG_DB_PATH", SETTINGS_REFERENCE["SECUREVAULT_ORG_DB_PATH"][0]))


def binary_db_path() -> Path:
    return Path(get("SECUREVAULT_BINARY_DB_PATH", SETTINGS_REFERENCE["SECUREVAULT_BINARY_DB_PATH"][0]))


def binary_storage_dir() -> Path:
    return Path(get("SECUREVAULT_BINARY_STORAGE_DIR", SETTINGS_REFERENCE["SECUREVAULT_BINARY_STORAGE_DIR"][0]))


def cors_origins() -> list[str]:
    raw = get("SECUREVAULT_CORS_ORIGINS", "") or ""
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    for origin in origins:
        if origin == "*" or not origin.startswith(("http://", "https://")):
            raise RuntimeError(
                "SECUREVAULT_CORS_ORIGINS must list exact http(s) origins; '*' is refused"
            )
    return origins


def is_development() -> bool:
    return (get("SECUREVAULT_ENV", "production") or "").strip().lower() == "development"


def upload_environment(environ=None) -> dict:
    """Merged settings for the encrypted-upload activation chain.

    ``SECUREVAULT_UPLOAD_DB_PATH`` defaults to ``SECUREVAULT_DB_PATH`` so the
    two can never silently point at different databases. If both are set and
    differ, startup fails with a clear error.
    """

    merged = environment(environ)
    main_db = Path(merged.get("SECUREVAULT_DB_PATH") or SETTINGS_REFERENCE["SECUREVAULT_DB_PATH"][0])
    upload_db = merged.get("SECUREVAULT_UPLOAD_DB_PATH")
    if not upload_db:
        merged["SECUREVAULT_UPLOAD_DB_PATH"] = str(main_db.resolve())
    elif Path(upload_db).resolve() != main_db.resolve():
        raise RuntimeError(
            "SECUREVAULT_UPLOAD_DB_PATH must point to the same file as "
            "SECUREVAULT_DB_PATH (leave it unset to use the main database)"
        )
    return merged
