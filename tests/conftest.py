import pytest

from app import create_app
from app.config import Config
from app.extensions import db as _db


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = "test-secret"
    MASTER_PASSPHRASE = "test-passphrase"
    WTF_CSRF_ENABLED = False


@pytest.fixture(scope="session")
def app():
    app = create_app(TestConfig)
    return app


@pytest.fixture(autouse=True)
def db(app):
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()
