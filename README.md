# Certificate Manager

A web-based X.509 Certificate Authority management application built with Python and Flask.

## Features

- **CA Management**: Create root and intermediate Certificate Authorities with RSA or EC keys
- **Certificate Issuance**: Generate certificates with SANs, key usage, and extended key usage
- **CSR Management**: Create or import Certificate Signing Requests, sign or reject them
- **Revocation**: Revoke certificates with standard reasons, generate CRLs
- **OCSP Responder**: Built-in OCSP endpoint for real-time certificate status checks
- **Public Endpoints**: Unauthenticated access to CRL downloads and CA certificates
- **Security**: Private keys encrypted at rest with Fernet (PBKDF2-derived key, 600k iterations)

## Quick Start

### Docker (recommended)

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# Build and run
docker-compose up --build
```

Navigate to `http://localhost:5000` and log in with the default credentials (admin/admin).

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

## Architecture

```
Flask App Factory
├── Models (SQLAlchemy)
│   ├── User
│   ├── CertificateAuthority
│   ├── Certificate
│   └── CertificateSigningRequest
├── Services
│   ├── crypto_utils    (Fernet key encryption)
│   ├── ca_service      (CA creation)
│   ├── cert_service    (certificate signing/export)
│   ├── csr_service     (CSR generation/import)
│   ├── crl_service     (revocation/CRL)
│   └── ocsp_service    (OCSP responder)
└── Routes (Blueprints)
    ├── auth            (login/logout)
    ├── dashboard       (stats)
    ├── ca              (CA CRUD)
    ├── certificates    (cert CRUD)
    ├── csr             (CSR CRUD)
    └── public          (CRL/CA/OCSP - no auth)
```
