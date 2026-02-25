# Certificate Manager - Development Guide

## Project Overview
Python/Flask web application for managing an X.509 Certificate Authority (CA).
Handles CA creation, certificate signing/revocation, CSR management, CRL generation, and OCSP responses.

## Tech Stack
- Python 3.13, Flask 3.1.3, SQLAlchemy 2.0.46, cryptography 46.0.5
- Bootstrap 5 (CDN), Gunicorn, SQLite

## Project Structure
- `app/` - Flask application (factory pattern in `__init__.py`)
- `app/models/` - SQLAlchemy models (User, CA, Certificate, CSR, AuditLog)
- `app/services/` - Business logic (crypto_utils, ca_service, cert_service, csr_service, crl_service, ocsp_service, audit_service)
- `app/routes/` - Flask blueprints (auth, dashboard, ca, certificates, csr, users, public)
- `app/decorators.py` - `role_required()`, `admin_required` access control decorators
- `app/templates/` - Jinja2 templates with Bootstrap 5
- `tests/` - pytest test suite

## Build & Run

### Docker (production)
```bash
docker-compose up --build
```
Requires `SECRET_KEY` and `MASTER_PASSPHRASE` env vars to be set (docker-compose will fail otherwise).

### Local development
```bash
pip install -r requirements.txt
flask --app "app:create_app()" run --debug
```

### Run tests
```bash
pip install pytest
python -m pytest tests/ -v
```

## Key Design Decisions
- **Private key encryption**: Fernet + PBKDF2-HMAC-SHA256 (600k iterations). Salt stored with ciphertext.
- **Master passphrase**: From `MASTER_PASSPHRASE` env var. Used for all key encrypt/decrypt.
- **OCSP**: Built-in responder at `/public/ocsp/<ca_id>`. Certificates include AIA extension.
- **Public endpoints**: CRL download and CA cert download require no auth.
- **Database**: SQLite, stored in `./data/` (Docker volume).

## Roles & Access Control
- **admin**: Full access to all routes (CAs, certificates, CSR signing/rejection, user management, audit log).
- **csr_user**: Can only create/upload CSRs and view their own. Cannot access CA, certificate, or user management routes.
- Routes are protected by `@admin_required` or `@login_required` decorators in `app/decorators.py`.
- CSR ownership enforced: `csr_user` can only see CSRs where `created_by == current_user.id`.
- Templates conditionally hide admin-only links/buttons using `{% if current_user.is_admin %}`.

## Audit Logging
- `app/services/audit_service.py` provides `log_action(action, target_type, target_id, details)`.
- Does NOT call `db.session.commit()` — caller commits as part of its transaction.
- All sensitive actions are logged: login/logout, CA/certificate/CSR operations, user management.
- Audit log viewable at `/users/audit-log` (admin only, paginated).

## Security Hardening
- **Insecure default rejection**: App refuses to start in non-debug, non-testing mode if `SECRET_KEY` or `MASTER_PASSPHRASE` are set to their insecure defaults (`sys.exit(1)`).
- **Session cookies**: HttpOnly, SameSite=Lax. Secure flag opt-in via `SESSION_COOKIE_SECURE=true` (for TLS proxy setups).
- **Session timeout**: Configurable via `SESSION_LIFETIME_MINUTES` (default 30).
- **Schema migration**: `_migrate_schema()` in `app/__init__.py` handles adding new columns to existing SQLite tables via ALTER TABLE.
- **Last-admin guards**: Cannot deactivate or demote the last active admin user.

## Environment Variables
- `SECRET_KEY` - Flask secret key
- `MASTER_PASSPHRASE` - Master passphrase for key encryption
- `DATABASE_URL` - SQLAlchemy database URI
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` - Default admin credentials
- `SERVER_NAME_FOR_OCSP` - Hostname for OCSP AIA URLs (default: localhost:5000)
- `SESSION_COOKIE_SECURE` - Require HTTPS for session cookies (default: false, set to true behind a TLS proxy)
- `SESSION_LIFETIME_MINUTES` - Session timeout in minutes (default: 30)
- `RATE_LIMIT_ENABLED` - Enable rate limiting (default: false, requires Flask-Limiter)
- `RATE_LIMIT_DEFAULT` - Default rate limit when enabled (default: 60/minute)
