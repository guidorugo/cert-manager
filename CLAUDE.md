# Certificate Manager - Development Guide

## Project Overview
Python/Flask web application for managing an X.509 Certificate Authority (CA).
Handles CA creation, certificate signing/revocation, CSR management, CRL generation, and OCSP responses.

## Tech Stack
- Python 3.13, Flask 3.1.3, SQLAlchemy 2.0.46, cryptography 46.0.5
- Bootstrap 5 (CDN), Gunicorn, SQLite

## Project Structure
- `.github/workflows/` - GitHub Actions CI (Docker build & push to GHCR)
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
docker compose up --build
```
Requires `SECRET_KEY` and `MASTER_PASSPHRASE` env vars to be set (docker compose will fail otherwise).

### Pre-built image (GHCR)
```bash
docker pull ghcr.io/guidorugo/cert-manager:latest
```
Or switch `docker-compose.yml` to use `image:` instead of `build:` (see commented line).

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

## CI/CD
- **GitHub Actions workflow**: `.github/workflows/docker-publish.yml`
- **Triggers**: Push to `master` (builds + pushes `latest`), `v*` tags (pushes semver tags), PRs (build-only validation).
- **Registry**: `ghcr.io/guidorugo/cert-manager` — uses `GITHUB_TOKEN`, no extra secrets needed.
- **`.dockerignore`**: Excludes `venv/`, `tests/`, `.env`, `.git/`, etc. from the Docker build context.

## Key Design Decisions
- **Private key encryption**: Fernet + PBKDF2-HMAC-SHA256 (600k iterations). Salt stored with ciphertext.
- **Master passphrase**: From `MASTER_PASSPHRASE` env var. Used for all key encrypt/decrypt.
- **OCSP**: Built-in responder at `/public/ocsp/<ca_id>`. Certificates include AIA extension.
- **Public endpoints**: CRL download and CA cert download require no auth.
- **Database**: SQLite, stored in `./data/` (Docker volume).

## Roles & Access Control
- **admin**: Full access to all routes (CAs, certificates, CSR signing/rejection, user management, audit log).
- **csr_requester**: Can create/upload CSRs and view their own CSRs and certificates. Cannot access CA management, user management, or certificate creation/revocation.
- Routes are protected by `@admin_required` or `@login_required` decorators in `app/decorators.py`.
- Ownership enforced: `csr_requester` can only see CSRs where `created_by == current_user.id` and certificates where `requested_by == current_user.id`.
- Templates conditionally hide admin-only links/buttons using `{% if current_user.is_admin %}`.

## Audit Logging
- `app/services/audit_service.py` provides `log_action(action, target_type, target_id, details)`.
- Does NOT call `db.session.commit()` — caller commits as part of its transaction.
- All sensitive actions are logged: login/logout, CA/certificate/CSR operations, user management.
- Audit log viewable at `/users/audit-log` (admin only, paginated).

## Security Hardening
- **Insecure default rejection**: App refuses to start in non-debug, non-testing mode if `SECRET_KEY`, `MASTER_PASSPHRASE`, or `ADMIN_PASSWORD` are set to their insecure defaults (`sys.exit(1)`).
- **Session cookies**: HttpOnly, SameSite=Lax. `SESSION_COOKIE_SECURE` configurable (default: false, set to true in production).
- **Session timeout**: Configurable via `SESSION_LIFETIME_MINUTES` (default 30).
- **Security headers**: `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` on all responses.
- **Open redirect protection**: Login `next` parameter validated to reject absolute/external URLs.
- **Timing attack mitigation**: Dummy hash computation on failed login for nonexistent users.
- **SRI**: Bootstrap CDN resources include `integrity` and `crossorigin` attributes.
- **Content-Disposition sanitization**: Filenames in download headers are sanitized to prevent header injection.
- **OCSP URL scheme**: Configurable via `OCSP_URL_SCHEME` (default: `http`, set to `https` in production).
- **Schema migration**: `_migrate_schema()` in `app/__init__.py` handles adding new columns to existing SQLite tables via ALTER TABLE.
- **Last-admin guards**: Cannot deactivate or demote the last active admin user.

## HTTP Basic Auth
- **Alternative to session auth**: Enables programmatic access via `curl -u user:pass`, scripts, and automation.
- **Stateless**: No session cookie created — each request authenticates independently.
- **CSRF bypass**: CSRF validation is skipped only for requests with **valid** Basic Auth credentials.
- **JSON error responses**: Basic Auth clients receive JSON `{"error": "..."}` for 401/403 instead of HTML redirects.
- **Audit logged**: Both success (`basic_auth_success`) and failure (`basic_auth_failed`) are logged.
- **Config**: `BASIC_AUTH_ENABLED` (default: true), `BASIC_AUTH_REALM` (default: "cert-manager").
- **HTTPS required in production**: Basic Auth sends credentials Base64-encoded (not encrypted).
- **Usage**: `curl -u admin:password https://host/ca/` or `curl -H "Authorization: Basic $(echo -n user:pass | base64)" https://host/ca/`.

## Environment Variables
- `SECRET_KEY` - Flask secret key
- `MASTER_PASSPHRASE` - Master passphrase for key encryption
- `DATABASE_URL` - SQLAlchemy database URI
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` - Default admin credentials
- `SERVER_NAME_FOR_OCSP` - Hostname for OCSP AIA URLs (default: localhost:5000)
- `SESSION_LIFETIME_MINUTES` - Session timeout in minutes (default: 30)
- `RATE_LIMIT_ENABLED` - Enable rate limiting (default: false, requires Flask-Limiter)
- `RATE_LIMIT_DEFAULT` - Default rate limit when enabled (default: 60/minute)
- `BASIC_AUTH_ENABLED` - Enable HTTP Basic Auth (default: true)
- `BASIC_AUTH_REALM` - Basic Auth realm name (default: cert-manager)
- `OCSP_URL_SCHEME` - URL scheme for OCSP AIA URLs in certificates (default: http, use https in production)
- `SESSION_COOKIE_SECURE` - Send session cookie only over HTTPS (default: false, set to true in production)
