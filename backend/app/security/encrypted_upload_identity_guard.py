
"""
Lesson 71: Windows deployment identity guard.

Encrypted uploads require an approved Windows
process identity before activation.

No keys, files, or database records are created.
"""

import re

from fastapi import FastAPI

from backend.app.security.encrypted_upload_activation import (
    ACTIVATION_SETTING
)

from backend.app.security.encrypted_upload_deployment_guard import (
    activate_encrypted_upload_safely
)

from backend.app.security.encrypted_upload_registration import (
    EncryptedUploadRegistrationError
)


import os

EXPECTED_SID_SETTING = (
    "SECUREVAULT_UPLOAD_WINDOWS_SID"
)

# Linux/macOS equivalent: the numeric user id the server must run as.
EXPECTED_UID_SETTING = (
    "SECUREVAULT_UPLOAD_EXPECTED_UID"
)


def read_current_process_sid():
    """
    Read the Windows SID of the process token.

    Use the process identity rather than trusting
    a username supplied in configuration.
    """

    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_QUERY
    )

    try:
        token_user = win32security.GetTokenInformation(
            token,
            win32security.TokenUser
        )

        sid = token_user[0]

        return win32security.ConvertSidToStringSid(
            sid
        )

    finally:
        token.Close()


def validate_windows_deployment_identity(
    environment
):
    """
    Verify the process runs as the expected
    Windows security principal.

    An expected SID must be configured explicitly.

    Do not return the SID or token information
    in application responses.
    """

    try:
        if environment is None:
            raise ValueError("Missing environment")

        if os.name != "nt":
            return _validate_posix_identity(environment)

        expected_sid = environment.get(
            EXPECTED_SID_SETTING
        )

        if type(expected_sid) is not str:
            raise ValueError(
                f"{EXPECTED_SID_SETTING} is not set "
                "(python -m backend.manage setup writes it)"
            )

        # Accept normal Windows SID notation.
        if re.fullmatch(
            r"S-1-(?:[0-9]+-)+[0-9]+",
            expected_sid
        ) is None:
            raise ValueError("Invalid SID format")

        actual_sid = read_current_process_sid()

        if (
            type(actual_sid) is not str
            or actual_sid != expected_sid
        ):
            raise ValueError(
                "server process is not running as the account "
                f"in {EXPECTED_SID_SETTING}"
            )

        return {
            "identity_verified": True
        }

    except Exception as error:
        raise EncryptedUploadRegistrationError(
            "Encrypted upload process identity "
            f"verification failed: {error}"
        ) from None


def _validate_posix_identity(environment):
    """Require the effective uid configured in SECUREVAULT_UPLOAD_EXPECTED_UID."""

    expected = environment.get(EXPECTED_UID_SETTING)

    if type(expected) is not str or not expected.isdigit():
        raise ValueError(
            f"{EXPECTED_UID_SETTING} must be the numeric uid of the server account"
        )

    if int(expected) != os.geteuid():
        raise ValueError(
            f"server process uid does not match {EXPECTED_UID_SETTING}"
        )

    return {"identity_verified": True}


def activate_encrypted_upload_with_identity(
    app,
    environment
):
    """
    Add Windows process identity verification
    before the existing Lesson 70 guard.

    Disabled:
        No SID setting is required.

    Enabled:
        Require a matching SID, then run all
        previous deployment checks.
    """

    if not isinstance(app, FastAPI):
        raise EncryptedUploadRegistrationError(
            "A FastAPI application is required"
        )

    if environment is None:
        raise EncryptedUploadRegistrationError(
            "Trusted environment is required"
        )

    try:
        enabled = environment.get(
            ACTIVATION_SETTING,
            "0"
        )
    except (AttributeError, TypeError):
        raise EncryptedUploadRegistrationError(
            "Invalid activation environment"
        ) from None

    if type(enabled) is not str or enabled not in (
        "0",
        "1"
    ):
        raise EncryptedUploadRegistrationError(
            "Invalid encrypted-upload activation setting"
        )

    if enabled == "1":
        validate_windows_deployment_identity(
            environment
        )

    # Keep all previous checks:
    # Lesson 70 filesystem safety
    # Lesson 69 activation control
    # Lesson 68 DB and KEK preflight
    # Lesson 67 JWT authentication
    return activate_encrypted_upload_safely(
        app,
        environment
    )
