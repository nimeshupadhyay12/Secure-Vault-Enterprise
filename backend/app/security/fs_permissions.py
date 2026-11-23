"""Least-privilege permissions for vault directories and secret files.

Used only by ``python -m backend.manage setup`` on paths the vault owns.

* Windows: replace the DACL with a *protected* one (no inheritance from the
  parent folder) that grants full control to the current user and SYSTEM
  only. New files inside inherit it. This is what the startup ACL guards
  then verify.
* Linux/macOS: chmod 0700 for directories, 0600 for files.
"""

from __future__ import annotations

import os
from pathlib import Path


SYSTEM_SID = "S-1-5-18"


def _current_user_sid():
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        return win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()


def restrict_to_owner(path) -> None:
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing to change permissions through a symbolic link")
    if not path.exists():
        raise FileNotFoundError(str(path))

    if os.name != "nt":
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
        return

    import ntsecuritycon
    import win32security

    inherit = (
        ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE
        if path.is_dir() else 0
    )
    dacl = win32security.ACL()
    for sid in (_current_user_sid(), win32security.ConvertStringSidToSid(SYSTEM_SID)):
        dacl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION, inherit, ntsecuritycon.FILE_ALL_ACCESS, sid
        )
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None,
    )
