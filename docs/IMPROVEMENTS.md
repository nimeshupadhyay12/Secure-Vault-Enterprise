# Hardening pass: what changed and why

Baseline: commit `db79a30`, `40 passed, 17 subtests passed` (Windows only).
Result: `129 passed, 1 skipped, 60 subtests passed` on Windows; CI green on `windows-latest` and `ubuntu-latest`.

## Bugs fixed

| Bug | Fix |
|---|---|
| SHA-256 stored but never re-checked on the main download path | Re-verified after decryption on every download path with `hmac.compare_digest`; returned as `X-Content-SHA256` and re-checked in the browser |
| Binary vault compared hashes with `!=` | Constant-time comparison; GCM failures and mismatches map to a distinct integrity error |
| `index_demo.py` used `history == ...` instead of an assignment | Fixed to `=` |
| Legacy `/auth/login` was a separate code path without the same checks | Now a deprecated alias of `/auth/token` (same lockout, timing equalisation and audit) |
| Unknown usernames answered much faster than wrong passwords (enumeration) | Dummy Argon2 verification for unknown users |
| Argon2id used library defaults | Parameters pinned in code, tested, and old hashes rehashed on login |
| `SECUREVAULT_UPLOAD_WINDOWS_SID` required but undocumented; main DB path hard-coded separately from `SECUREVAULT_UPLOAD_DB_PATH` | One settings module; the upload DB defaults to the main DB and a mismatch fails at startup; every variable documented |
| Startup checks failed with generic messages | Each guard now reports the reason (missing setting, unsafe nesting, broad ACL, wrong account, missing key file, missing schema) and the API names the fix |
| No way to create the KEK or the binary-vault table | `python -m backend.manage setup` |
| `pywin32` in requirements broke installation on Linux | Platform marker |
| The old two-step text upload could leave metadata-only records | One-step `/documents/encrypted` removes the metadata row if encryption fails |
| `create-user --password-stdin` stored a BOM-prefixed password when piped from PowerShell | Leading BOM stripped |

## Features added

### Central configuration (`backend/app/core/settings.py`)
All `SECUREVAULT_*` values resolve environment first, then `runtime/securevault.env`, then defaults. `SETTINGS_REFERENCE` documents each one and the README table mirrors it. Paths that were hard-coded in the binary vault and organiser now come from here.

### Pluggable key provider (`security/key_provider.py`, `windows_kek_store.py`)
DPAPI remains the default on Windows; new key files are bound to their key id through DPAPI entropy and legacy files still load. The `env` provider wraps the KEK with AES-256-GCM under `SECUREVAULT_MASTER_KEY` (AAD = key id), which lets the vault and CI run on Linux.

### Authentication hardening (`api/auth.py`, `security/tokens.py`, `sessions.py`, `passwords.py`)
15-minute HS256 access tokens with pinned algorithm and required `sub, iss, aud, iat, nbf, exp, jti, typ`. Opaque refresh tokens stored as SHA-256, rotated on every use; reuse revokes the family. `/auth/logout` revokes the access token `jti` and the refresh family (or all sessions). Per-username lockout with 429 + `Retry-After`. Placeholder JWT secrets are refused outside `SECUREVAULT_ENV=development`, which uses a random per-process secret instead of any default. NIST-style password policy for new accounts.

### Integrity verification and migration 004 (`security/integrity.py`, `migrations/migration_004.py`)
`encrypted_document_keys.content_sha256` (nullable, added with `ALTER TABLE`, no rewrite) records the plaintext fingerprint. Uploads whose bytes do not match the metadata SHA-256 are rejected. Existing rows still decrypt; their fingerprint is recorded on the first GCM-authenticated read. The AAD already bound ciphertext and wrapped keys to owner, document id, storage id and filename, so no format change was needed; tests now prove it.

### Tamper-evident audit log (`security/audit_log.py`)
Each entry stores the previous entry's hash and its own SHA-256 or HMAC-SHA256 (`SECUREVAULT_AUDIT_KEY`) over a canonical JSON form. Routes record sign-ins, failures, lockouts, refreshes, reuse, logouts, user creation, document create/rename/delete, encrypted and binary uploads/downloads, integrity failures, organiser changes and KEK creation/rotation. `manage audit-verify` recomputes the chain and detects edits, deletions, reordering and unkeyed entries after keyed ones. The dashboard activity feed now reads the caller's own audit entries.

### One-command setup and preflight (`core/bootstrap.py`, `manage.py`)
`setup` creates restricted directories (protected DACL for user + SYSTEM on Windows, 0700 elsewhere), the three databases with migrations 001-004, a provider-protected KEK (never replaced), and a config file with a random JWT secret, audit key and process identity, then runs the startup preflight. `check` runs that preflight on demand. POSIX equivalents of the Windows ACL and SID guards make enabled mode work on Linux.

### General document types (`security/document_types.py`, `POST /documents/encrypted`)
One allow-list for `.txt .pdf .docx .xlsx .png .jpg .jpeg` with structural checks, zip traversal / encrypted-member / compression-ratio limits and a configurable size limit (5 MiB default). The new endpoint validates, records size and SHA-256 from the real bytes, encrypts and stores in one request. The frontend uses it for every type.

### KEK rotation (`security/kek_rotation.py`, `manage rotate-kek`)
Unwraps each DEK with the KEK named in its row and re-wraps it under a new KEK with a fresh nonce and the same AAD, in one transaction per database, then switches the active key id. Ciphertext files are never touched; tampered rows stop the rotation with nothing changed.

### HTTP hardening (`core/http_security.py`)
Security headers on every response, deny-all CSP on API responses, `no-store` on auth/document responses, optional HSTS, a request-body cap enforced from `Content-Length` and while streaming, CORS disabled unless exact origins are configured (no wildcard, no credentials), and a switch to hide Swagger.

### App factory (`api_main.create_app`)
Lets tests build the full application in enabled and disabled mode; startup failures raise with the guard's reason.

### Frontend (`frontend/vault.js`, `index.html`)
Tokens stay in memory; a single shared refresh runs on 401 and the request is retried once; logout calls the server. Uploads accept all supported types; downloads are hashed in the browser and refused on mismatch.

### Tests and CI
New test modules: `test_auth_hardening.py`, `test_tokens_passwords_keys.py`, `test_integrity_tamper.py`, `test_audit_log.py`, `test_setup_and_documents.py`, `test_documents_and_organizer.py`, `test_rotation_and_http.py`, plus `conftest.py` isolation. GitHub Actions runs Windows (full, real DPAPI/ACL/SID) and Ubuntu (provider-independent), each followed by a setup/check/app-import/audit-verify smoke test.

## Database schema changes

| Table / column | Change |
|---|---|
| `encrypted_document_keys.content_sha256` | New nullable TEXT (64 lowercase hex), migration 004 |
| `refresh_tokens` | New: user_id, family_id, token_hash (unique), issued_at, expires_at, family_expires_at, used_at, revoked_at, revoke_reason |
| `revoked_access_tokens` | New: jti (PK), user_id, expires_at |
| `auth_failures` | New: username (PK), failure_count, window_start, locked_until |
| `audit_log` | New: created_at, event_type, user_id, document_id, outcome, detail, prev_hash, entry_hash, mac_alg |
| `binary_documents` (binary DB) | Schema now defined in code (`initialize_binary_database`) with CHECK constraints |
| `schema_migrations` | Records version 4 |

No existing column or ciphertext format was changed; documents encrypted before this pass still decrypt.

## Not done

* Per-IP throttling (lockout is per username only).
* External anchoring of the audit-log head hash (truncation of the newest entries is not detectable from the chain alone).
* Screenshots were not retaken after the UI wording changes.
