"""HTTP hardening applied to every response.

* Security headers: nosniff, frame denial, no referrer, restrictive
  Permissions-Policy and COOP; a deny-all CSP on API responses (the /vault
  page sets its own script-src 'self' policy; Swagger pages are exempt).
* ``Cache-Control: no-store`` on authentication and document responses so
  tokens and decrypted content are never cached.
* Optional HSTS (``SECUREVAULT_HSTS=1``) when served behind HTTPS.
* Request-size cap (``SECUREVAULT_MAX_REQUEST_BYTES``) enforced from the
  ``Content-Length`` header and while streaming bodies without one.
* CORS is off (same-origin only) unless ``SECUREVAULT_CORS_ORIGINS`` lists
  exact origins; ``*`` is refused and credentials are never allowed.
"""

from __future__ import annotations

from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from backend.app.core import settings


DEFAULT_MAX_REQUEST_BYTES = 6 * 1024 * 1024
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
NO_STORE_PREFIXES = ("/auth", "/documents", "/vault/binary", "/vault/organize")
CSP_EXEMPT_PREFIXES = ("/docs", "/redoc", "/vault/assets/")
CSP_EXEMPT_PATHS = ("/vault",)


class SecurityMiddleware:
    """Pure ASGI middleware (also caps streamed request bodies)."""

    def __init__(self, app, max_request_bytes: int, hsts: bool):
        self.app = app
        self.max_request_bytes = max_request_bytes
        self.hsts = hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        headers = dict(scope.get("headers") or [])
        length = headers.get(b"content-length")
        if length is not None:
            try:
                too_large = int(length) > self.max_request_bytes
            except ValueError:
                too_large = True
            if too_large:
                response = JSONResponse({"detail": "Request body too large"}, status_code=413)
                return await response(scope, receive, send)

        state = {"received": 0, "too_large": False, "replied": False}

        async def reply_413():
            if state["replied"]:
                return
            state["replied"] = True
            body = b'{"detail":"Request body too large"}'
            await send({"type": "http.response.start", "status": 413, "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"x-content-type-options", b"nosniff"),
            ]})
            await send({"type": "http.response.body", "body": body})

        async def limited_receive():
            message = await receive()
            if message["type"] == "http.request":
                state["received"] += len(message.get("body", b""))
                if state["received"] > self.max_request_bytes:
                    # Stop feeding the application; it sees a disconnect and
                    # whatever it answers is replaced by a 413 below.
                    state["too_large"] = True
                    return {"type": "http.disconnect"}
            return message

        async def secure_send(message):
            if state["too_large"]:
                await reply_413()
                return
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                ]
                if path not in CSP_EXEMPT_PATHS and not path.startswith(CSP_EXEMPT_PREFIXES):
                    extra.append((b"content-security-policy", API_CSP.encode()))
                if path.startswith(NO_STORE_PREFIXES):
                    extra.append((b"cache-control", b"no-store"))
                if self.hsts:
                    extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = list(message.get("headers", [])) + [
                    (name, value) for name, value in extra if name not in existing
                ]
            await send(message)

        try:
            await self.app(scope, limited_receive, secure_send)
        except Exception:
            if not state["too_large"]:
                raise
            # The application failed because its body was cut off.
            await reply_413()


def install(app) -> None:
    origins = settings.cors_origins()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            expose_headers=["X-Content-SHA256", "Retry-After"],
            max_age=600,
        )
    app.add_middleware(
        SecurityMiddleware,
        max_request_bytes=settings.get_int("SECUREVAULT_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES, minimum=1024),
        hsts=settings.get_bool("SECUREVAULT_HSTS", False),
    )
