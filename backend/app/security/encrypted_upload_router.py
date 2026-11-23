
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request
)

from backend.app.database.owned_document_repository import (
    create_owned_document,
    delete_owned_document
)

from backend.app.security import audit_log, document_types

from backend.app.security.integrity import sha256_hex

from backend.app.security.encrypted_upload_preflight import (
    max_upload_bytes
)

from backend.app.security.encrypted_upload_service import (
    EncryptedUploadServiceError,
    UploadOwnershipError,
    store_encrypted_upload
)


def create_encrypted_upload_router(
    *,
    db_path,
    storage_dir,
    key_directory,
    key_id,
    authenticated_owner_dependency
):
    """
    Create an isolated encrypted-upload router.

    The caller MUST supply an authentication
    dependency that validates the user first.

    Do not use a request-supplied user ID.

    This factory does not mount itself into
    the existing SecureVault FastAPI app.
    """

    if not callable(authenticated_owner_dependency):
        raise ValueError(
            "Trusted authentication dependency required"
        )

    router = APIRouter()

    async def _read_bounded_body(request):
        """Require application/octet-stream and read at most the
        configured limit, stopping as soon as it is exceeded.
        The data is held in memory only; plaintext never touches disk."""

        content_type = request.headers.get(
            "content-type", ""
        ).split(";", 1)[0].strip().lower()

        if content_type != "application/octet-stream":
            raise HTTPException(
                status_code=415,
                detail="Unsupported media type"
            )

        chunks = []
        total_bytes = 0
        limit = max_upload_bytes()

        async for chunk in request.stream():

            total_bytes += len(chunk)

            if total_bytes > limit:
                raise HTTPException(
                    status_code=413,
                    detail="Upload exceeds size limit"
                )

            if chunk:
                chunks.append(chunk)

        if total_bytes == 0:
            raise HTTPException(
                status_code=400,
                detail="Empty upload rejected"
            )

        return b"".join(chunks)

    @router.post(
        "/documents/{document_id}/encrypted-content",
        status_code=201
    )
    async def upload_encrypted_document(
        document_id: int,
        request: Request,
        filename: str = Query(...),
        authenticated_owner_id: int = Depends(
            authenticated_owner_dependency
        )
    ):
        """
        Receive a bounded binary request body,
        then call the Lesson 64 upload service.
        """

        # Step 1: Never trust an owner ID
        # supplied directly by an HTTP client.
        if (
            type(authenticated_owner_id) is not int
            or authenticated_owner_id <= 0
        ):
            raise HTTPException(
                status_code=401,
                detail="Authentication required"
            )

        # Steps 2-3: raw binary body, bounded read.
        content = await _read_bounded_body(request)

        # Step 4: Authorize using the trusted
        # identity supplied by the dependency.
        try:
            result = store_encrypted_upload(
                db_path=db_path,
                storage_dir=storage_dir,
                key_directory=key_directory,
                document_id=document_id,
                authenticated_owner_id=(
                    authenticated_owner_id
                ),
                filename=filename,
                content=content,
                key_id=key_id
            )

        except UploadOwnershipError:
            # Do not reveal another user's
            # document existence.
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            ) from None

        except EncryptedUploadServiceError as error:
            audit_log.record_event(
                "encrypted_upload_rejected",
                user_id=authenticated_owner_id,
                document_id=document_id,
                outcome="failure",
                db_path=db_path
            )
            raise HTTPException(
                status_code=400,
                detail=f"Encrypted upload rejected: {error}"
            ) from None

        audit_log.record_event(
            "encrypted_upload",
            user_id=authenticated_owner_id,
            document_id=document_id,
            detail={"size_bytes": result["size_bytes"]},
            db_path=db_path
        )

        # Step 5: Return metadata only.
        # Never include plaintext or encryption keys.
        return {
            "stored": True,
            "document_id": result["document_id"],
            "storage_id": result["storage_id"],
            "size_bytes": result["size_bytes"],
            "sha256": result["sha256"],
            "encrypted": True
        }

    @router.post(
        "/documents/encrypted",
        status_code=201
    )
    async def upload_new_encrypted_document(
        request: Request,
        filename: str = Query(..., min_length=1, max_length=105),
        authenticated_owner_id: int = Depends(
            authenticated_owner_dependency
        )
    ):
        """
        One-step encrypted upload for any supported document type
        (.txt, .pdf, .docx, .xlsx, .png, .jpg/.jpeg).

        Creates the owned metadata record from the actual bytes
        (size + SHA-256), then encrypts and stores the content.
        If encryption fails the metadata record is removed again,
        so no metadata-only orphan is left behind.
        """

        if (
            type(authenticated_owner_id) is not int
            or authenticated_owner_id <= 0
        ):
            raise HTTPException(
                status_code=401,
                detail="Authentication required"
            )

        content = await _read_bounded_body(request)

        try:
            media_type = document_types.validate_document(
                filename, content
            )
        except ValueError as error:
            raise HTTPException(
                status_code=422,
                detail=str(error)
            ) from None

        digest = sha256_hex(content)

        try:
            document_id = create_owned_document(
                owner_user_id=authenticated_owner_id,
                filename=filename,
                size_bytes=len(content),
                sha256=digest,
                db_path=db_path
            )
        except Exception:
            raise HTTPException(
                status_code=503,
                detail="Document metadata unavailable"
            ) from None

        try:
            result = store_encrypted_upload(
                db_path=db_path,
                storage_dir=storage_dir,
                key_directory=key_directory,
                document_id=document_id,
                authenticated_owner_id=authenticated_owner_id,
                filename=filename,
                content=content,
                key_id=key_id
            )
        except (EncryptedUploadServiceError, UploadOwnershipError) as error:
            # Compensate: remove the metadata row we just created.
            delete_owned_document(
                document_id, authenticated_owner_id, db_path
            )
            audit_log.record_event(
                "encrypted_upload_rejected",
                user_id=authenticated_owner_id,
                outcome="failure",
                db_path=db_path
            )
            raise HTTPException(
                status_code=400,
                detail=f"Encrypted upload rejected: {error}"
            ) from None

        audit_log.record_event(
            "document_created",
            user_id=authenticated_owner_id,
            document_id=document_id,
            db_path=db_path
        )
        audit_log.record_event(
            "encrypted_upload",
            user_id=authenticated_owner_id,
            document_id=document_id,
            detail={"size_bytes": len(content), "media_type": media_type},
            db_path=db_path
        )

        return {
            "id": document_id,
            "filename": filename,
            "size_bytes": len(content),
            "sha256": result["sha256"],
            "media_type": media_type,
            "storage_id": result["storage_id"],
            "encrypted": True
        }

    return router
