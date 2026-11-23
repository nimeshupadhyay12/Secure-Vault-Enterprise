"""Authenticated download of encrypted documents.

Uses the same validated JWT owner dependency as the encrypted upload router.
The plaintext is re-verified against its recorded SHA-256 fingerprint before
it leaves the server, and the fingerprint is returned in ``X-Content-SHA256``
so the client can verify it too. No raw KEK, wrapped DEK, filesystem path,
or plaintext is logged.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from backend.app.security import audit_log
from backend.app.security.dpapi_document_reader import (
    DocumentIntegrityError,
    DocumentRecoveryError,
    read_document_with_dpapi,
)
from backend.app.security.integrity import sha256_hex
from backend.app.security.jwt_encrypted_upload_integration import (
    get_verified_upload_owner,
)


def create_jwt_encrypted_download_router(*, db_path, storage_dir, key_directory):
    """Build an isolated router; only register it after upload preflight succeeds."""
    router = APIRouter(tags=["Encrypted Documents"])

    @router.get("/documents/{document_id}/encrypted-content")
    def download_encrypted_document(
        document_id: int,
        authenticated_owner_id: int = Depends(get_verified_upload_owner),
    ):
        if type(document_id) is not int or document_id <= 0:
            raise HTTPException(status_code=404, detail="Document not found")
        if type(authenticated_owner_id) is not int or authenticated_owner_id <= 0:
            raise HTTPException(status_code=401, detail="Authentication required")

        try:
            plaintext = read_document_with_dpapi(
                db_path=db_path,
                storage_dir=storage_dir,
                key_directory=key_directory,
                document_id=document_id,
                owner_user_id=authenticated_owner_id,
            )
        except LookupError:
            # Same response for unknown documents and documents owned by others.
            raise HTTPException(status_code=404, detail="Document not found") from None
        except DocumentIntegrityError:
            audit_log.record_event(
                "integrity_failure", user_id=authenticated_owner_id,
                document_id=document_id, outcome="failure",
                detail={"path": "encrypted-content"}, db_path=db_path,
            )
            raise HTTPException(
                status_code=500, detail="Document failed integrity verification"
            ) from None
        except DocumentRecoveryError:
            # Do not reveal file paths, key IDs, or decryption errors.
            raise HTTPException(status_code=500, detail="Document unavailable") from None

        if type(plaintext) is not bytes:
            raise HTTPException(status_code=500, detail="Document unavailable")

        audit_log.record_event(
            "encrypted_download", user_id=authenticated_owner_id,
            document_id=document_id, db_path=db_path,
        )

        # No filename header: client uses its own authenticated metadata list.
        return Response(
            content=plaintext,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "Content-Disposition": "attachment",
                "X-Content-SHA256": sha256_hex(plaintext),
            },
        )

    return router
