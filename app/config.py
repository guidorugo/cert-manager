import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    MASTER_PASSPHRASE = os.environ.get("MASTER_PASSPHRASE", "dev-passphrase")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///cert-manager.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
    SERVER_NAME_FOR_OCSP = os.environ.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
