# Certificate Manager - Development Guide

## Project Overview
Python/Flask web application for managing an X.509 Certificate Authority (CA).
Handles CA creation, certificate signing/revocation, CSR management, CRL generation, and OCSP responses.

## Tech Stack
- Python 3.13, Flask 3.1.3, SQLAlchemy 2.0.46, cryptography 46.0.5
- Bootstrap 5 (CDN), Gunicorn, SQLite

## Project Structure
- `app/` - Flask application (factory pattern in `__init__.py`)
- `app/models/` - SQLAlchemy models (User, CA, Certificate, CSR)
- `app/services/` - Business logic (crypto_utils, ca_service, cert_service, csr_service, crl_service, ocsp_service)
- `app/routes/` - Flask blueprints (auth, dashboard, ca, certificates, csr, public)
- `app/templates/` - Jinja2 templates with Bootstrap 5
- `tests/` - pytest test suite

## Build & Run

### Docker (production)
```bash
docker-compose up --build
```

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

## Environment Variables
- `SECRET_KEY` - Flask secret key
- `MASTER_PASSPHRASE` - Master passphrase for key encryption
- `DATABASE_URL` - SQLAlchemy database URI
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` - Default admin credentials
- `SERVER_NAME_FOR_OCSP` - Hostname for OCSP AIA URLs (default: localhost:5000)
