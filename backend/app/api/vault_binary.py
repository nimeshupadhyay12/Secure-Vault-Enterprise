"""Isolated SecureVault binary-document API (PDF/OOXML/PNG/JPEG).

Demonstration only, single process; no change to original metadata or .txt APIs.
File length <= 5 MiB; image/OOXML checks are structural, not malware scanning.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from backend.app.api.auth import get_current_user
from backend.app.core import settings
from backend.app.security import audit_log, document_types
from backend.app.security.integrity import IntegrityVerificationError, verify_sha256
from backend.app.security.windows_kek_store import load_protected_kek

API = APIRouter(prefix='/vault/binary', tags=['Encrypted binary documents'])


# Locations come from the central settings module (SECUREVAULT_BINARY_DB_PATH,
# SECUREVAULT_BINARY_STORAGE_DIR) and are resolved per call.
def _binary_db():
    return settings.binary_db_path()


def _binary_dir():
    return settings.binary_storage_dir()


LIMIT = 5 * 1024 * 1024
FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.(?:pdf|docx|xlsx|png|jpg|jpeg)$', re.I)
MEDIA = {'.pdf':'application/pdf','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
         '.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
         '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg'}


BINARY_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS binary_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL CHECK (owner_id > 0),
        filename TEXT NOT NULL,
        media_type TEXT NOT NULL,
        size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
        sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
        storage_id TEXT NOT NULL UNIQUE CHECK (length(storage_id) = 32 AND storage_id NOT GLOB '*[^0-9a-f]*'),
        nonce BLOB CHECK (nonce IS NULL OR length(nonce) = 12),
        wrap_nonce BLOB CHECK (wrap_nonce IS NULL OR length(wrap_nonce) = 12),
        wrapped_dek BLOB CHECK (wrapped_dek IS NULL OR length(wrapped_dek) = 48),
        created_at TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'ready'))
    )""",
    "CREATE INDEX IF NOT EXISTS idx_binary_documents_owner ON binary_documents(owner_id, status, id)",
)


def initialize_binary_database(path=None):
    """Create the binary-document database and table (idempotent).

    Called by ``python -m backend.manage setup``; never by HTTP requests.
    """
    path = Path(path) if path is not None else _binary_db()
    if path.is_symlink():
        raise RuntimeError('Binary database path cannot be a symbolic link')
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db, db:
        for statement in BINARY_SCHEMA:
            db.execute(statement)
    return path


def _open_database(path, *, readonly=False):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Required existing database unavailable')
    uri = path.resolve().as_uri() + '?mode=ro' if readonly else str(path)
    conn = sqlite3.connect(uri, uri=readonly, timeout=8)
    conn.row_factory = sqlite3.Row
    if not readonly: conn.execute('PRAGMA foreign_keys=ON')
    return conn


def _check_storage():
    root = _binary_dir()
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError('Protected binary storage unavailable')
    # Directory is created by `python -m backend.manage setup`, never by HTTP requests.
    return root


def _kek():
    key_dir = settings.get('SECUREVAULT_UPLOAD_KEK_DIR', '') or ''
    key_id = settings.get('SECUREVAULT_UPLOAD_KEK_ID', '') or ''
    if not key_dir or not key_id:
        raise RuntimeError('Protected key configuration missing')
    key = load_protected_kek(Path(key_dir), key_id)['kek']
    if type(key) is not bytes or len(key) != 32:
        raise RuntimeError('Invalid protected demo key')
    return key


def _user(user):
    uid = user.get('user_id') if isinstance(user, dict) else None
    if type(uid) is not int or uid < 1:
        raise HTTPException(status_code=401,detail='Authentication required')
    return uid


def validate(filename, data):
    """Limited structural checks; these do not establish that a file is harmless.

    Shares the allow-list in security/document_types.py (minus .txt, which
    belongs to the main encrypted-content path).
    """
    if type(filename) is not str or not FILENAME_RE.fullmatch(filename) or '..' in filename:
        raise ValueError('Unsupported or unsafe filename; PDF, DOCX, XLSX, PNG, JPG only')
    if type(data) is not bytes or not 1 <= len(data) <= LIMIT:
        raise ValueError('File must contain 1 byte to 5 MiB')
    return document_types.check_content(filename, data)


def _aad(owner, file_id, storage, filename):
    return json.dumps(['SV-BINARY-1',owner,file_id,storage,filename],separators=(',',':')).encode()


def _cipher_path(storage):
    if not re.fullmatch('[0-9a-f]{32}',storage): raise RuntimeError('Invalid ciphertext reference')
    root=_check_storage()
    path=root/(storage+'.svbin')
    if path.is_symlink(): raise RuntimeError('Linked ciphertext refused')
    return path


def create_binary(*, owner, filename, body):
    media=validate(filename,body)
    root=_check_storage()
    kek=_kek()
    storage=secrets.token_hex(16)
    file_path=_cipher_path(storage)
    tmp=file_path.with_name(file_path.name+'.pending')
    digest=hashlib.sha256(body).hexdigest()
    with closing(_open_database(_binary_db())) as db:
        try:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''INSERT INTO binary_documents(owner_id,filename,media_type,size_bytes,sha256,storage_id,nonce,wrap_nonce,wrapped_dek,created_at,status)
                 VALUES(?,?,?,?,?,?,NULL,NULL,NULL,?, 'pending')''',
                 (owner,filename,media,len(body),digest,storage,datetime.now(timezone.utc).isoformat(timespec='seconds')))
            file_id=db.execute('SELECT last_insert_rowid()').fetchone()[0]
            dek=secrets.token_bytes(32); nonce=secrets.token_bytes(12); wrap_nonce=secrets.token_bytes(12)
            aad=_aad(owner,file_id,storage,filename)
            wrapped=AESGCM(kek).encrypt(wrap_nonce,dek,aad+b'|key')
            ciphertext=AESGCM(dek).encrypt(nonce,body,aad+b'|file')
            with tmp.open('xb') as stream:
                stream.write(ciphertext);stream.flush();os.fsync(stream.fileno())
            os.replace(tmp,file_path)
            db.execute("UPDATE binary_documents SET nonce=?,wrap_nonce=?,wrapped_dek=?,status='ready' WHERE id=?",
                       (nonce,wrap_nonce,wrapped,file_id))
            db.commit()
            return {'id':file_id,'filename':filename,'size_bytes':len(body),'media_type':media,'encrypted':True}
        except BaseException:
            db.rollback()
            for target in (tmp,file_path):
                try: target.unlink(missing_ok=True)
                except OSError: pass
            raise


def _find(owner, file_id):
    with closing(_open_database(_binary_db(),readonly=True)) as db:
        row=db.execute('SELECT * FROM binary_documents WHERE id=? AND owner_id=? AND status=?',
                       (file_id,owner,'ready')).fetchone()
        return dict(row) if row else None


def read_binary(*,owner,file_id):
    row=_find(owner,file_id)
    if row is None: raise LookupError('Document not found')
    path=_cipher_path(row['storage_id'])
    if not path.is_file() or path.stat().st_size>LIMIT+16:
        raise RuntimeError('Ciphertext unavailable')
    aad=_aad(owner,file_id,row['storage_id'],row['filename'])
    try:
        dek=AESGCM(_kek()).decrypt(row['wrap_nonce'],row['wrapped_dek'],aad+b'|key')
        data=AESGCM(dek).decrypt(row['nonce'],path.read_bytes(),aad+b'|file')
    except InvalidTag:
        raise IntegrityVerificationError('Authenticated decryption failed') from None
    if len(data)!=row['size_bytes']:
        raise IntegrityVerificationError('Size verification failed')
    # Constant-time comparison against the fingerprint recorded at upload.
    verify_sha256(data,row['sha256'])
    return row,data


def delete_binary(*,owner,file_id):
    root=_check_storage()
    with closing(_open_database(_binary_db())) as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute("SELECT storage_id FROM binary_documents WHERE id=? AND owner_id=? AND status='ready'",(file_id,owner)).fetchone()
        if row is None:
            db.rollback();return False
        path=_cipher_path(row['storage_id'])
        if not path.is_file():
            db.rollback(); raise RuntimeError('Ciphertext missing; metadata preserved')
        staged=path.with_name(path.name+'.deleting')
        if staged.exists():
            db.rollback(); raise RuntimeError('Staged deletion requires review')
        os.replace(path,staged)
        try:
            db.execute('DELETE FROM binary_documents WHERE id=? AND owner_id=?',(file_id,owner))
            db.commit()
        except BaseException:
            db.rollback(); os.replace(staged,path);raise
        # On unlink failure, staged ciphertext remains for explicit operator cleanup.
        staged.unlink(missing_ok=True)
        return True


@API.get('/files')
def list_files(user=Depends(get_current_user),limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0)):
    owner=_user(user)
    with closing(_open_database(_binary_db(),readonly=True)) as db:
        count=db.execute("SELECT COUNT(*) FROM binary_documents WHERE owner_id=? AND status='ready'",(owner,)).fetchone()[0]
        rows=db.execute("SELECT id,filename,media_type,size_bytes,sha256,created_at FROM binary_documents WHERE owner_id=? AND status='ready' ORDER BY id DESC LIMIT ? OFFSET ?",(owner,limit,offset)).fetchall()
    return {'files':[dict(r) for r in rows],'total':count,'limit':limit,'offset':offset}


@API.post('/files',status_code=201)
async def upload_file(request:Request,filename:str=Query(...),user=Depends(get_current_user)):
    owner=_user(user)
    if request.headers.get('content-type','').split(';')[0].lower().strip()!='application/octet-stream':
        raise HTTPException(415,'Use application/octet-stream')
    chunks=[];total=0
    async for chunk in request.stream():
        total+=len(chunk)
        if total>LIMIT: raise HTTPException(413,'File exceeds 5 MiB limit')
        chunks.append(chunk)
    try: result=create_binary(owner=owner,filename=filename,body=b''.join(chunks))
    except ValueError as exc: raise HTTPException(422,str(exc)) from None
    except Exception: raise HTTPException(503,'Encrypted storage temporarily unavailable') from None
    audit_log.record_event('binary_upload',user_id=owner,detail={'binary_id':result['id'],'size_bytes':result['size_bytes']})
    return result


@API.get('/files/{file_id}/download')
def download_file(file_id:int,user=Depends(get_current_user)):
    owner=_user(user)
    if file_id<=0: raise HTTPException(404,'Document not found')
    try: row,data=read_binary(owner=owner,file_id=file_id)
    except LookupError: raise HTTPException(404,'Document not found') from None
    except IntegrityVerificationError:
        audit_log.record_event('integrity_failure',user_id=owner,outcome='failure',detail={'path':'binary','binary_id':file_id})
        raise HTTPException(500,'Document failed integrity verification') from None
    except Exception: raise HTTPException(503,'Document recovery unavailable') from None
    audit_log.record_event('binary_download',user_id=owner,detail={'binary_id':file_id})
    name=quote(row['filename'],safe='')
    return Response(data,headers={'Content-Disposition':f"attachment; filename*=UTF-8''{name}", 'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Content-SHA256':row['sha256']},media_type='application/octet-stream')


@API.delete('/files/{file_id}')
def delete_file(file_id:int,user=Depends(get_current_user)):
    owner=_user(user)
    if file_id<=0: raise HTTPException(404,'Document not found')
    try: removed=delete_binary(owner=owner,file_id=file_id)
    except Exception: raise HTTPException(503,'Deletion requires operator review') from None
    if not removed: raise HTTPException(404,'Document not found')
    audit_log.record_event('binary_delete',user_id=owner,detail={'binary_id':file_id})
    return {'deleted':True,'id':file_id}
