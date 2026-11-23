"""SecureVault operator commands.

    python -m backend.manage setup [--runtime-dir DIR] [--key-id ID] [--provider dpapi|env]
    python -m backend.manage check
    python -m backend.manage create-user USERNAME
    python -m backend.manage audit-verify [--db PATH]
    python -m backend.manage rotate-kek --new-key-id ID

Run from the repository root. Configuration is read from the environment and
``runtime/securevault.env`` (see backend/app/core/settings.py).
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys


def cmd_setup(args) -> int:
    from backend.app.core.bootstrap import SetupError, run_setup

    try:
        run_setup(runtime_dir=args.runtime_dir, key_id=args.key_id,
                  provider=args.provider, dev_master_key=args.dev_master_key)
    except SetupError as error:
        print(f"Setup incomplete: {error}", file=sys.stderr)
        return 2
    print("Next: python -m backend.manage create-user <name>, then start the API:")
    print("  uvicorn backend.api_main:app --host 127.0.0.1 --port 8766")
    return 0


def cmd_check(args) -> int:
    from backend.app.core.bootstrap import run_check

    ok, message = run_check()
    print(("OK: " if ok else "FAILED: ") + message, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


def cmd_rotate_kek(args) -> int:
    import os
    from pathlib import Path

    from backend.app.core import settings
    from backend.app.core.bootstrap import update_config_value
    from backend.app.security import audit_log
    from backend.app.security.kek_rotation import KekRotationError, rotate_kek

    old_key_id = settings.get("SECUREVAULT_UPLOAD_KEK_ID")
    key_dir = settings.get("SECUREVAULT_UPLOAD_KEK_DIR")
    if not old_key_id or not key_dir:
        print("SECUREVAULT_UPLOAD_KEK_ID and SECUREVAULT_UPLOAD_KEK_DIR must be configured "
              "(run setup first).", file=sys.stderr)
        return 2
    try:
        result = rotate_kek(db_path=settings.db_path(), binary_db=settings.binary_db_path(),
                            key_dir=Path(key_dir), old_key_id=old_key_id, new_key_id=args.new_key_id)
    except (KekRotationError, ValueError, OSError) as error:
        print(f"Rotation stopped: {error}", file=sys.stderr)
        return 1
    audit_log.record_event("kek_rotated", detail={"from": old_key_id, "to": args.new_key_id, **result},
                           db_path=settings.db_path())
    print(f"Re-wrapped {result['documents_rewrapped']} document keys and "
          f"{result['binary_rewrapped']} binary keys; no ciphertext file was touched.")
    if os.environ.get("SECUREVAULT_UPLOAD_KEK_ID"):
        print(f"SECUREVAULT_UPLOAD_KEK_ID is set in the environment: change it to {args.new_key_id}.")
    else:
        update_config_value(settings.config_file_path(), "SECUREVAULT_UPLOAD_KEK_ID", args.new_key_id)
        print(f"Config updated: SECUREVAULT_UPLOAD_KEK_ID={args.new_key_id}")
    print(f"The old KEK file ({old_key_id}) was kept for older backups; delete it once they are retired.")
    return 0


def cmd_audit_verify(args) -> int:
    from backend.app.security import audit_log

    report = audit_log.verify_chain(args.db)
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["ok"]:
        print(f"Audit chain OK: {report['entries']} entries, head {report['head_hash']}")
        print("Store the head hash somewhere else to detect truncation later.")
        return 0
    print(f"AUDIT CHAIN BROKEN at entry {report['first_bad_id']}: {report['reason']}", file=sys.stderr)
    return 1


def cmd_create_user(args) -> int:
    from backend.app.database.user_repository import register_user

    if args.password_stdin:
        # Windows shells may prefix piped text with a byte-order mark.
        password = sys.stdin.readline().lstrip("﻿").rstrip("\r\n")
    else:
        password = getpass.getpass("Password (12+ characters): ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            return 2
    try:
        user_id = register_user(args.username, password)
    except ValueError as error:
        print(f"User not created: {error}", file=sys.stderr)
        return 2
    print(f"Created user {args.username!r} with id {user_id}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m backend.manage", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup", help="Create directories, databases, KEK and config (idempotent)")
    setup.add_argument("--runtime-dir", default=None, help="Default: <repo>/runtime")
    setup.add_argument("--key-id", default=None, help="KEK identifier (default securevault-kek-1)")
    setup.add_argument("--provider", choices=("dpapi", "env"), default=None,
                       help="Key provider (default: dpapi on Windows, env elsewhere)")
    setup.add_argument("--dev-master-key", action="store_true",
                       help="env provider only: generate a master key into the config file (development)")
    setup.set_defaults(func=cmd_setup)

    check = sub.add_parser("check", help="Run the startup preflight and explain any failure")
    check.set_defaults(func=cmd_check)

    audit = sub.add_parser("audit-verify", help="Recompute the audit-log hash chain")
    audit.add_argument("--db", default=None, help="Database path (default: SECUREVAULT_DB_PATH)")
    audit.set_defaults(func=cmd_audit_verify)

    rotate = sub.add_parser("rotate-kek", help="Re-wrap every data key under a new KEK (stop the API first)")
    rotate.add_argument("--new-key-id", required=True)
    rotate.set_defaults(func=cmd_rotate_kek)

    user = sub.add_parser("create-user", help="Create a vault user (password prompted)")
    user.add_argument("username")
    user.add_argument("--password-stdin", action="store_true",
                      help="Read the password from the first line of stdin (automation)")
    user.set_defaults(func=cmd_create_user)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
