import pytest
from datetime import timedelta

from app import create_app
from app.config import Config


class InsecureConfig(Config):
    TESTING = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False


class TestSecurityDefaults:
    """Insecure defaults are rejected in production."""

    def test_insecure_defaults_rejected_in_production(self):
        with pytest.raises(SystemExit):
            create_app(InsecureConfig)

    def test_insecure_defaults_allowed_in_testing(self):
        class SafeTestConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = "sqlite://"
            SECRET_KEY = "dev-secret-key"
            MASTER_PASSPHRASE = "dev-passphrase"
            WTF_CSRF_ENABLED = False

        app = create_app(SafeTestConfig)
        assert app is not None


class TestSessionConfig:
    """Session cookie security settings."""

    def test_session_cookie_httponly(self, app):
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True

    def test_session_cookie_samesite(self, app):
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    def test_session_lifetime(self, app):
        assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=30)
