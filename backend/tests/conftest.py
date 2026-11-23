"""Test-session isolation.

Runs before any backend module is imported, so module-level settings such as
DATABASE_PATH point at a throw-away directory instead of the real vault.

* On Windows the default key provider (DPAPI) is used, so DPAPI is exercised.
* Elsewhere the 'env' key provider is selected with a random master key.
"""

import base64
import os
import secrets
import shutil
import tempfile
from pathlib import Path

_TEST_ROOT = Path(tempfile.mkdtemp(prefix="securevault-tests-"))

os.environ["SECUREVAULT_CONFIG_FILE"] = str(_TEST_ROOT / "no-config-file.env")
os.environ["SECUREVAULT_DB_PATH"] = str(_TEST_ROOT / "main.db")
os.environ["SECUREVAULT_ORG_DB_PATH"] = str(_TEST_ROOT / "organization.db")
os.environ["SECUREVAULT_BINARY_DB_PATH"] = str(_TEST_ROOT / "binary.db")
os.environ["SECUREVAULT_BINARY_STORAGE_DIR"] = str(_TEST_ROOT / "binary-files")
os.environ.pop("SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD", None)
os.environ.pop("SECUREVAULT_AUDIT_KEY", None)

if os.name != "nt":
    os.environ.setdefault("SECUREVAULT_KEY_PROVIDER", "env")
    os.environ.setdefault(
        "SECUREVAULT_MASTER_KEY",
        base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    )


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TEST_ROOT, ignore_errors=True)
