"""Tamper-evident security audit log (hash chain).

Every entry stores ``prev_hash`` (the previous entry's hash) and
``entry_hash`` = MAC(canonical JSON of the entry including prev_hash).

* With ``SECUREVAULT_AUDIT_KEY`` (32+ chars) the MAC is HMAC-SHA256, so an
  attacker who can write to the database but does not hold the key cannot
  forge or re-chain entries.
* Without the key the chain uses plain SHA-256. That still detects edits or
  deletions in the middle of the log, but someone with write access could
  rebuild the whole chain. ``verify_chain`` reports which mode each entry used.

Truncating the newest entries cannot be detected from the chain alone;
record the head hash printed by ``python -m backend.manage audit-verify``
somewhere else if you need that guarantee.

Audit writes are best effort: a failure is logged and never breaks the
request that triggered it (availability over completeness for this MVP).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from backend.app.core import settings
from backend.app.database import db as db_module
from backend.app.database.db import apply_security_schema


LOGGER = logging.getLogger("securevault.audit")

GENESIS_HASH = "0" * 64

EVENT_TYPES = frozenset({
    "login_success", "login_failure", "login_locked",
    "token_refreshed", "refresh_token_reuse", "refresh_rejected", "logout",
    "user_created",
    "document_created", "document_renamed", "document_deleted",
    "document_access_denied",
    "encrypted_upload", "encrypted_upload_rejected", "encrypted_download",
    "integrity_failure",
    "binary_upload", "binary_download", "binary_delete",
    "organization_updated",
    "kek_created", "kek_rotated",
})

# Events a user may see about themselves in the dashboard.
USER_VISIBLE_EVENTS = EVENT_TYPES - {"kek_created", "kek_rotated"}


def _default_db():
    return Path(db_module.DATABASE_PATH)


def _audit_key():
    key = settings.get("SECUREVAULT_AUDIT_KEY", "") or ""
    if key and len(key) < 32:
        raise RuntimeError("SECUREVAULT_AUDIT_KEY must contain at least 32 characters")
    return key.encode("utf-8") if key else None


def _canonical(entry: dict) -> bytes:
    fields = {
        "created_at": entry["created_at"],
        "event_type": entry["event_type"],
        "user_id": entry["user_id"],
        "document_id": entry["document_id"],
        "outcome": entry["outcome"],
        "detail": entry["detail"],
        "prev_hash": entry["prev_hash"],
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_hash(entry: dict, mac_alg: str, key: bytes | None) -> str:
    data = _canonical(entry)
    if mac_alg == "hmac-sha256":
        if key is None:
            raise RuntimeError("Audit HMAC key unavailable")
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    if mac_alg == "sha256":
        return hashlib.sha256(data).hexdigest()
    raise RuntimeError("Unknown audit MAC algorithm")


def record_event(
    event_type,
    *,
    user_id=None,
    document_id=None,
    outcome="success",
    detail=None,
    db_path=None,
):
    """Append one event. Never raises; returns the new entry id or None."""

    db_path = Path(db_path) if db_path else _default_db()
    try:
        if event_type not in EVENT_TYPES:
            raise ValueError("Unknown audit event type")
        if outcome not in ("success", "failure", "denied"):
            raise ValueError("Invalid audit outcome")
        if not db_path.is_file():
            raise FileNotFoundError("Audit database unavailable")

        key = _audit_key()
        mac_alg = "hmac-sha256" if key else "sha256"
        detail_text = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"))
        if len(detail_text) > 2000:
            raise ValueError("Audit detail too large")

        with closing(sqlite3.connect(db_path, timeout=10)) as connection:
            apply_security_schema(connection)
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            try:
                last = connection.execute(
                    "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
                entry = {
                    "created_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                    "event_type": event_type,
                    "user_id": user_id,
                    "document_id": document_id,
                    "outcome": outcome,
                    "detail": detail_text,
                    "prev_hash": last[0] if last else GENESIS_HASH,
                }
                entry_hash = _compute_hash(entry, mac_alg, key)
                cursor = connection.execute(
                    """
                    INSERT INTO audit_log (created_at, event_type, user_id,
                        document_id, outcome, detail, prev_hash, entry_hash, mac_alg)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (entry["created_at"], event_type, user_id, document_id,
                     outcome, detail_text, entry["prev_hash"], entry_hash, mac_alg),
                )
                connection.commit()
                return cursor.lastrowid
            except Exception:
                connection.rollback()
                raise
    except Exception as error:
        LOGGER.warning("Audit event %s not recorded: %s", event_type, type(error).__name__)
        return None


def verify_chain(db_path=None):
    """Recompute every hash. Returns a report dict; ``ok`` is False on any break."""

    db_path = Path(db_path) if db_path else _default_db()
    report = {"ok": True, "entries": 0, "head_hash": GENESIS_HASH,
              "first_bad_id": None, "reason": None, "modes": {}}
    if not db_path.is_file():
        report.update(ok=False, reason="database not found")
        return report

    key = _audit_key()
    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        has_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_log'"
        ).fetchone()
        if not has_table:
            return report
        rows = connection.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()

    expected_prev = GENESIS_HASH
    seen_hmac = False
    for row in rows:
        entry = dict(row)
        report["entries"] += 1
        report["modes"][entry["mac_alg"]] = report["modes"].get(entry["mac_alg"], 0) + 1
        if entry["mac_alg"] == "hmac-sha256":
            seen_hmac = True
        elif seen_hmac:
            # Once the chain is keyed, an unkeyed entry means someone without
            # the key appended or re-chained entries (downgrade attempt).
            report.update(ok=False, first_bad_id=entry["id"],
                          reason="unkeyed entry after keyed entries (downgrade)")
            return report
        if entry["prev_hash"] != expected_prev:
            report.update(ok=False, first_bad_id=entry["id"],
                          reason="chain broken (entry removed, inserted or reordered)")
            return report
        try:
            recomputed = _compute_hash(entry, entry["mac_alg"], key)
        except RuntimeError as error:
            report.update(ok=False, first_bad_id=entry["id"], reason=str(error))
            return report
        if not hmac.compare_digest(recomputed, entry["entry_hash"]):
            report.update(ok=False, first_bad_id=entry["id"],
                          reason="entry contents modified")
            return report
        expected_prev = entry["entry_hash"]

    report["head_hash"] = expected_prev
    return report


def list_user_events(user_id, limit=30, db_path=None):
    """Owner-scoped view of the audit log for the dashboard."""

    db_path = Path(db_path) if db_path else _default_db()
    if not db_path.is_file():
        return []
    uri = db_path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        has_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_log'"
        ).fetchone()
        if not has_table:
            return []
        visible = sorted(USER_VISIBLE_EVENTS)
        placeholders = ",".join("?" for _ in visible)
        rows = connection.execute(
            "SELECT id, document_id, event_type, outcome, created_at "
            "FROM audit_log WHERE user_id = ? AND event_type IN (" + placeholders + ") "
            "ORDER BY id DESC LIMIT ?",
            (user_id, *visible, limit),
        ).fetchall()
    return [dict(r) for r in rows]
