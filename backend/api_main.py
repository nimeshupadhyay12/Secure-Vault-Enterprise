"""SecureVault Enterprise FastAPI application.

Run:  uvicorn backend.api_main:app --host 127.0.0.1 --port 8766

All configuration comes from ``backend.app.core.settings`` (environment
variables first, then ``runtime/securevault.env`` written by
``python -m backend.manage setup``).
"""

from fastapi import Depends, FastAPI

from backend.app.core import settings

from backend.app.security.encrypted_upload_key_file_guard import (
    activate_encrypted_upload_with_key_file_guard
)

from backend.app.api.health import router as health_router
from backend.app.api.documents import router as documents_router
from backend.app.api.document_metadata import router as metadata_router
from backend.app.api.auth import router as auth_router
from backend.app.api.private_documents import router as private_documents_router
from backend.app.api.vault_ui import router as vault_ui_router
from backend.app.api.vault_organizer import (
    router as vault_organizer_router,
    observe_actions as vault_observe_actions,
)

from backend.app.security.legacy_routes import reject_legacy_document_access


app = FastAPI(
    title="SecureVault Enterprise API",
    version="0.8.0"
)


# Health endpoint
app.include_router(health_router)


# OLD DOCUMENT APIS - RETIRED
# The dependency rejects every request with HTTP 410.
# The routes are also hidden from Swagger.
app.include_router(
    documents_router,
    dependencies=[Depends(reject_legacy_document_access)],
    include_in_schema=False
)

app.include_router(
    metadata_router,
    dependencies=[Depends(reject_legacy_document_access)],
    include_in_schema=False
)


# Authentication routes
app.include_router(auth_router)

# JWT-protected document metadata routes
app.include_router(private_documents_router)

# Public UI shell only. All document APIs still require JWT.
app.include_router(vault_ui_router)


# Encrypted storage is disabled unless SECUREVAULT_ENABLE_ENCRYPTED_UPLOAD=1.
# Enabled mode runs the full preflight chain (key-file ACL, directory ACLs,
# process identity, path topology, schema, key recovery) and refuses to start
# if anything is wrong. Never suppress that error.
_upload_environment = settings.upload_environment()

encrypted_upload_activation = (
    activate_encrypted_upload_with_key_file_guard(
        app=app,
        environment=_upload_environment
    )
)


# Attach download only after the enabled-mode guards have validated the
# deployment and registered the encrypted upload route.
if encrypted_upload_activation.get("registered") is True:
    from backend.app.security.encrypted_upload_registration import (
        check_encrypted_upload_configuration,
    )
    from backend.app.security.encrypted_download_router import (
        create_jwt_encrypted_download_router,
    )

    _encrypted_config = check_encrypted_upload_configuration(_upload_environment)
    app.include_router(
        create_jwt_encrypted_download_router(
            db_path=_encrypted_config["db_path"],
            storage_dir=_encrypted_config["storage_dir"],
            key_directory=_encrypted_config["key_directory"],
        )
    )


@app.get("/")
def home():
    return {
        "message": "Welcome to SecureVault Enterprise API"
    }


# Folder / tag / favourite organisation and the user's activity feed.
app.include_router(vault_organizer_router)
vault_observe_actions(app)


# Binary-document vault: registered only after the same guards pass.
if encrypted_upload_activation.get("registered") is True:
    from backend.app.api.vault_binary import API as vault_binary_router
    app.include_router(vault_binary_router)
