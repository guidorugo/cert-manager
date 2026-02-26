import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    MASTER_PASSPHRASE = os.environ.get("MASTER_PASSPHRASE", "dev-passphrase")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///cert-manager.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
    SERVER_NAME_FOR_OCSP = os.environ.get("SERVER_NAME_FOR_OCSP", "localhost:5000")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get("SESSION_LIFETIME_MINUTES", "30"))
    )

    RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "false").lower() == "true"
    RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "60/minute")

    BASIC_AUTH_ENABLED = os.environ.get("BASIC_AUTH_ENABLED", "true").lower() == "true"
    BASIC_AUTH_REALM = os.environ.get("BASIC_AUTH_REALM", "cert-manager")

    _INSECURE_SECRET_KEY = "dev-secret-key"
    _INSECURE_PASSPHRASE = "dev-passphrase"
