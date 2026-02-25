import pytest

from app import create_app
from app.config import Config
from app.extensions import db as _db
from app.models.user import User


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


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_user(db):
    user = User(username="testadmin", role="admin")
    user.set_password("adminpass")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def csr_user(db):
    user = User(username="testcsruser", role="csr_user")
    user.set_password("csrpass")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def auth_admin(client, admin_user):
    client.post("/auth/login", data={
        "username": "testadmin",
        "password": "adminpass",
    })
    return client


@pytest.fixture
def auth_csr_user(client, csr_user):
    client.post("/auth/login", data={
        "username": "testcsruser",
        "password": "csrpass",
    })
    return client
