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
from backend.app.api.vault_organizer import router as vault_organizer_router

from backend.app.security.legacy_routes import reject_legacy_document_access


from backend.app.security.encrypted_upload_registration import (
    EncryptedUploadRegistrationError,
)


def create_app(environment=None):
    """Build the application.

    ``environment`` defaults to the merged settings (environment variables
    plus the config file). Enabled encrypted storage that fails any preflight
    check raises at startup with the reason; it is never silently disabled.
    """

    if environment is None:
        environment = settings.upload_environment()

    app = FastAPI(
        title="SecureVault Enterprise API",
        version="0.8.0"
    )

    # Health endpoint
    app.include_router(health_router)

    # OLD DOCUMENT APIS - RETIRED (HTTP 410, hidden from Swagger).
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
    # process identity, path topology, schema, key recovery).
    try:
        activation = activate_encrypted_upload_with_key_file_guard(
            app=app,
            environment=environment
        )
    except EncryptedUploadRegistrationError as error:
        raise RuntimeError(
            f"SecureVault encrypted storage could not start: {error}. "
            "Run `python -m backend.manage check` for details, or "
            "`python -m backend.manage setup` to initialise the vault."
        ) from None

    if activation.get("registered") is True:
        from backend.app.security.encrypted_upload_registration import (
            check_encrypted_upload_configuration,
        )
        from backend.app.security.encrypted_download_router import (
            create_jwt_encrypted_download_router,
        )
        from backend.app.api.vault_binary import API as vault_binary_router

        config = check_encrypted_upload_configuration(environment)
        app.include_router(
            create_jwt_encrypted_download_router(
                db_path=config["db_path"],
                storage_dir=config["storage_dir"],
                key_directory=config["key_directory"],
            )
        )
        # Binary-document vault: registered only after the same guards pass.
        app.include_router(vault_binary_router)

    @app.get("/")
    def home():
        return {
            "message": "Welcome to SecureVault Enterprise API"
        }

    # Folder / tag / favourite organisation and the user's activity feed.
    app.include_router(vault_organizer_router)

    app.state.securevault_activation = activation
    return app


app = create_app()
