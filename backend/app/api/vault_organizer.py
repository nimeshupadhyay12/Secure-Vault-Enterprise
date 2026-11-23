"""Folder / tag / favourite metadata (sidecar DB) and the user's activity feed.

The activity feed reads the owner's own entries from the tamper-evident,
hash-chained audit log (backend.app.security.audit_log). Security events are
written there directly by the routes that perform the action.
"""
from __future__ import annotations
import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from backend.app.api.auth import get_current_user
from backend.app.core import settings
from backend.app.security import audit_log



def _main_db():
    return settings.db_path()


def _side_db():
    return settings.org_db_path()


router = APIRouter(prefix='/vault/organize', tags=['Vault Organization'])
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$')


def _connect(path: Path, *, readonly=False):
    path = Path(path).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('Vault database unavailable')
    if readonly:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)
    else:
        connection = sqlite3.connect(path, timeout=3)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_sidecar(path=None):
    """Explicit installer-only migration. Never run automatically on requests."""
    path = Path(path) if path is not None else _side_db()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('Existing isolated organization database required')
    with closing(_connect(path)) as db, db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('''CREATE TABLE IF NOT EXISTS document_organization (
            document_id INTEGER PRIMARY KEY,
            folder TEXT NOT NULL DEFAULT 'Unfiled',
            tags TEXT NOT NULL DEFAULT '[]',
            favorite INTEGER NOT NULL DEFAULT 0 CHECK(favorite IN (0,1)),
            updated_at TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS vault_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            document_id INTEGER,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL)''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_vault_events_owner ON vault_events(owner_user_id,id DESC)')


def _owner(user):
    value = user.get('user_id') if isinstance(user, dict) else None
    if type(value) is not int or value < 1:
        raise HTTPException(401, 'Authentication required')
    return value


def _owned(document_id, owner_user_id):
    if type(document_id) is not int or document_id < 1:
        raise HTTPException(404, 'Document not found')
    with closing(_connect(_main_db(), readonly=True)) as db:
        record = db.execute('SELECT id,filename FROM owned_documents WHERE id=? AND owner_user_id=?', (document_id,owner_user_id)).fetchone()
    if record is None:
        raise HTTPException(404, 'Document not found')
    return dict(record)


def _validate_label(label):
    if not isinstance(label, str) or not NAME_RE.fullmatch(label) or '..' in label:
        raise HTTPException(422, 'Folder and tags must use 1–32 safe characters')
    return label


class OrganizationUpdate(BaseModel):
    folder: str = 'Unfiled'
    tags: list[str] = []
    favorite: bool = False


@router.get('/snapshot')
def snapshot(user=Depends(get_current_user)):
    owner = _owner(user)
    with closing(_connect(_main_db(), readonly=True)) as db:
        rows = db.execute('SELECT id FROM owned_documents WHERE owner_user_id=? ORDER BY id DESC LIMIT 500', (owner,)).fetchall()
        ids = [int(r['id']) for r in rows]
        has_keys = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='encrypted_document_keys'").fetchone() is not None
        encrypted = set()
        if has_keys and ids:
            for row in db.execute('''SELECT k.document_id FROM encrypted_document_keys k
                      JOIN owned_documents d ON d.id=k.document_id WHERE d.owner_user_id=?''',(owner,)):
                encrypted.add(row['document_id'])
    organized = {}
    if ids:
        with closing(_connect(_side_db(), readonly=True)) as db:
            for row in db.execute('SELECT document_id,folder,tags,favorite FROM document_organization WHERE document_id IN ('+','.join('?' for _ in ids)+')',ids):
                try: tags = json.loads(row['tags'])
                except (ValueError,TypeError): tags=[]
                organized[row['document_id']] = {'folder':row['folder'],'tags':tags,'favorite':bool(row['favorite'])}
    return {'items': {str(i): {**organized.get(i,{'folder':'Unfiled','tags':[],'favorite':False}), 'has_encrypted_key_record':i in encrypted} for i in ids},
            'scope':'First 500 owned records by ID; key-record presence does not prove ciphertext recoverability'}


@router.put('/documents/{document_id}')
def save_organization(document_id: int, payload: OrganizationUpdate, user=Depends(get_current_user)):
    owner = _owner(user)
    _owned(document_id,owner)
    folder = _validate_label(payload.folder)
    if len(payload.tags) > 8:
        raise HTTPException(422,'Maximum 8 tags')
    tags = list(dict.fromkeys(_validate_label(t) for t in payload.tags))
    with closing(_connect(_side_db())) as db, db:
        db.execute('''INSERT INTO document_organization(document_id,folder,tags,favorite,updated_at)
            VALUES (?,?,?,?,?) ON CONFLICT(document_id) DO UPDATE SET folder=excluded.folder,tags=excluded.tags,
            favorite=excluded.favorite,updated_at=excluded.updated_at''',
            (document_id, folder, json.dumps(tags), int(payload.favorite),datetime.now(timezone.utc).isoformat(timespec='seconds')))
    audit_log.record_event('organization_updated', user_id=owner, document_id=document_id)
    return {'id':document_id,'folder':folder,'tags':tags,'favorite':payload.favorite}


@router.get('/activity')
def activity(limit:int=Query(30,ge=1,le=100), user=Depends(get_current_user)):
    owner = _owner(user)
    try:
        events = audit_log.list_user_events(owner, limit=limit)
    except Exception:
        raise HTTPException(503, 'Activity history unavailable') from None
    return {'events':events, 'notice':'Your entries from the hash-chained audit log; verify the chain with python -m backend.manage audit-verify'}


def observe_actions(app):
    """Kept for backwards compatibility. Events are now recorded by the routes
    themselves into the tamper-evident audit log, so nothing is observed here."""
    return app
