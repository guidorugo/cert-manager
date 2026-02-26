# Certificate Manager

A web-based X.509 Certificate Authority management application built with Python and Flask.

## Features

- **CA Management**: Create root and intermediate Certificate Authorities with RSA or EC keys
- **Certificate Issuance**: Generate certificates with SANs, key usage, and extended key usage
- **CSR Management**: Create or import Certificate Signing Requests, sign or reject them
- **Revocation**: Revoke certificates with standard reasons, generate CRLs
- **OCSP Responder**: Built-in OCSP endpoint for real-time certificate status checks
- **Public Endpoints**: Unauthenticated access to CRL downloads and CA certificates
- **Role-Based Access Control**: Admin and CSR User roles with enforced separation of duties
- **Audit Logging**: Every sensitive action logged with user, timestamp, IP, and details
- **User Management**: Admin UI for creating users, assigning roles, and managing accounts
- **HTTP Basic Auth**: Stateless API access via `curl -u user:pass` for scripts and automation, alongside session-based browser auth
- **Security**: Private keys encrypted at rest with Fernet (PBKDF2-derived key, 600k iterations), session hardening, insecure-default rejection

## Quick Start

### Docker (recommended)

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# Build and run
docker compose up --build
```

Navigate to `http://localhost:5000` and log in with the default credentials (admin/admin).

### Pre-built Image (GHCR)

A pre-built image is published to GitHub Container Registry on every push to `master`.

```bash
# Pull the latest image
docker pull ghcr.io/guidorugo/cert-manager:latest

# Run with required environment variables
docker run -d \
  -p 5000:5000 \
  -v ./data:/app/data \
  -e SECRET_KEY=your-secret-key \
  -e MASTER_PASSPHRASE=your-passphrase \
  ghcr.io/guidorugo/cert-manager:latest
```

You can also use the pre-built image with docker compose by commenting out the `build` line and uncommenting the `image` line in `docker-compose.yml`.

### Local Development

```bash
pip install -r requirements.txt
export SECRET_KEY=dev-secret
export MASTER_PASSPHRASE=dev-passphrase
flask --app "app:create_app()" run --debug
```

## Usage

### 1. Create a Root CA

Go to **CAs > Create CA**, fill in the subject details, choose key type (RSA 2048/4096 or EC 256/384), and set validity.

### 2. Issue a Certificate

Go to **Certificates > Create Certificate**, select the issuing CA, fill in subject and SANs.

### 3. Manage CSRs

Go to **CSRs > Create CSR** to generate or upload a CSR. Then sign it with a CA from the CSR detail page.

### 4. Revoke & CRL

Revoke a certificate from its detail page. Generate a CRL from the CA detail page.

### 5. Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `/public/ca/<id>.crt` | Download CA certificate (PEM) |
| `/public/crl/<id>.crl` | Download CRL (DER) |
| `/public/crl/<id>.pem` | Download CRL (PEM) |
| `/public/ocsp/<id>` | OCSP responder (POST, DER) |

### OCSP Testing

```bash
openssl ocsp \
  -issuer ca.pem \
  -cert cert.pem \
  -url http://localhost:5000/public/ocsp/1 \
  -resp_text
```

## API Reference

Cert Manager is a web application with form-based (HTML) endpoints. All authenticated routes use session cookies set at login. Public endpoints require no authentication.

### Authentication

#### HTTP Basic Auth (recommended for scripts/automation)

All authenticated endpoints support HTTP Basic Auth — no session or CSRF token needed:

```bash
# Simple access with Basic Auth
curl -u admin:admin http://localhost:5000/ca/

# POST requests work without CSRF tokens
curl -u admin:admin -X POST http://localhost:5000/ca/1/crl
```

#### Session Cookies (browser / legacy)

Alternatively, authenticate via session cookie:

```bash
# Login and save session cookie
curl -c cookies.txt -X POST http://localhost:5000/auth/login \
  -d "username=admin&password=admin"

# Use session cookie for subsequent requests
curl -b cookies.txt http://localhost:5000/ca/
```

### Roles

| Role | Access |
|------|--------|
| `admin` | Full access: CAs, certificates, CSR signing/rejection, user management, audit log |
| `csr_user` | Create/upload CSRs, view own CSRs, dashboard with own stats |
| `csr_requester` | Create/upload CSRs, view own CSRs — intended for users who only submit certificate requests |

### Public Endpoints (no authentication)

These endpoints are designed for automated consumption by PKI clients, browsers, and OCSP validators.

| Method | Endpoint | Content-Type | Description |
|--------|----------|-------------|-------------|
| GET | `/public/ca/<ca_id>.crt` | `application/x-pem-file` | Download CA certificate (PEM) |
| GET | `/public/crl/<ca_id>.crl` | `application/pkix-crl` | Download CRL (DER) |
| GET | `/public/crl/<ca_id>.pem` | `application/x-pem-file` | Download CRL (PEM) |
| POST | `/public/ocsp/<ca_id>` | `application/ocsp-response` | OCSP responder (send DER-encoded OCSP request) |

```bash
# Download a CA certificate
curl -O http://localhost:5000/public/ca/1.crt

# Download a CRL
curl -O http://localhost:5000/public/crl/1.crl

# OCSP query with OpenSSL
openssl ocsp \
  -issuer ca.pem -cert cert.pem \
  -url http://localhost:5000/public/ocsp/1 \
  -resp_text
```

### Authenticated Endpoints

All authenticated endpoints support HTTP Basic Auth or session cookies (see [Authentication](#authentication) above). CSRF tokens are required for session-based POST requests but are not needed when using Basic Auth.

#### CA Management (admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ca/` | List all Certificate Authorities |
| GET, POST | `/ca/create` | Create or import a CA |
| POST | `/ca/detect-parent` | Detect parent CA for an imported certificate (JSON response) |
| GET | `/ca/<ca_id>` | View CA details |
| POST | `/ca/<ca_id>/crl` | Generate a new CRL |

#### Certificate Management (admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/certificates/` | List all certificates |
| GET, POST | `/certificates/create` | Issue a new certificate |
| GET | `/certificates/<cert_id>` | View certificate details |
| GET, POST | `/certificates/<cert_id>/revoke` | Revoke a certificate |
| GET | `/certificates/<cert_id>/download` | Download certificate (`?format=pem\|der\|pkcs12`) |
| GET | `/certificates/<cert_id>/download-key` | Download private key (PEM) |

```bash
# Download a certificate in PEM format
curl -b cookies.txt -O http://localhost:5000/certificates/1/download?format=pem

# Download in DER format
curl -b cookies.txt -O http://localhost:5000/certificates/1/download?format=der

# Download as PKCS#12 bundle
curl -b cookies.txt -O "http://localhost:5000/certificates/1/download?format=pkcs12&password=changeit"

# Download private key
curl -b cookies.txt -O http://localhost:5000/certificates/1/download-key
```

#### CSR Management (all authenticated users)

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/csr/` | Any | List CSRs (admin sees all, CSR users see own) |
| GET, POST | `/csr/create` | Any | Create or import a CSR |
| GET | `/csr/<csr_id>` | Any | View CSR details (CSR users can only view own) |
| GET, POST | `/csr/<csr_id>/sign` | Admin | Sign a pending CSR |
| POST | `/csr/<csr_id>/reject` | Admin | Reject a pending CSR |

#### User Management (admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users/` | List all users |
| GET, POST | `/users/create` | Create a new user |
| GET, POST | `/users/<user_id>/edit` | Change user role |
| POST | `/users/<user_id>/toggle-active` | Activate or deactivate a user |
| GET, POST | `/users/<user_id>/reset-password` | Reset a user's password |
| GET | `/users/audit-log` | View audit log (paginated, `?page=N`) |

#### Dashboard & Auth

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | `/` | Any | Dashboard (role-conditional stats) |
| GET, POST | `/auth/login` | None | Login page |
| GET | `/auth/logout` | Any | Logout |

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-secret-key` | Flask session secret |
| `MASTER_PASSPHRASE` | `dev-passphrase` | Key encryption passphrase |
| `DATABASE_URL` | `sqlite:///cert-manager.db` | Database URI |
| `ADMIN_USERNAME` | `admin` | Default admin username |
| `ADMIN_PASSWORD` | `admin` | Default admin password |
| `SERVER_NAME_FOR_OCSP` | `localhost:5000` | Server hostname for OCSP AIA URLs |
| `SESSION_LIFETIME_MINUTES` | `30` | Session timeout in minutes |
| `RATE_LIMIT_ENABLED` | `false` | Enable rate limiting (requires Flask-Limiter) |
| `RATE_LIMIT_DEFAULT` | `60/minute` | Default rate limit when enabled |
| `BASIC_AUTH_ENABLED` | `true` | Enable HTTP Basic Auth for programmatic access |
| `BASIC_AUTH_REALM` | `cert-manager` | Basic Auth realm name in `WWW-Authenticate` header |

## Architecture

```
Flask App Factory
├── Models (SQLAlchemy)
│   ├── User            (roles: admin, csr_user)
│   ├── CertificateAuthority
│   ├── Certificate
│   ├── CertificateSigningRequest
│   └── AuditLog
├── Services
│   ├── crypto_utils    (Fernet key encryption)
│   ├── ca_service      (CA creation)
│   ├── cert_service    (certificate signing/export)
│   ├── csr_service     (CSR generation/import)
│   ├── crl_service     (revocation/CRL)
│   ├── ocsp_service    (OCSP responder)
│   └── audit_service   (audit logging)
└── Routes (Blueprints)
    ├── auth            (login/logout)
    ├── dashboard       (role-conditional stats)
    ├── ca              (CA CRUD - admin only)
    ├── certificates    (cert CRUD - admin only)
    ├── csr             (CSR CRUD - ownership enforced)
    ├── users           (user management - admin only)
    └── public          (CRL/CA/OCSP - no auth)
```
