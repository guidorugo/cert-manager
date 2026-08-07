"""The footer shows the application version (small-print)."""

from app import create_app
from app._version import __version__

from tests.conftest import TestConfig


def test_footer_shows_baked_version(client):
    resp = client.get("/auth/login")
    assert resp.status_code == 200
    assert f"v{__version__}".encode() in resp.data


def test_app_version_env_override(monkeypatch):
    # A deployment can override the displayed version via APP_VERSION (read at
    # app-creation time by the context processor).
    monkeypatch.setenv("APP_VERSION", "9.9.9-test")
    app = create_app(TestConfig)
    resp = app.test_client().get("/auth/login")
    assert resp.status_code == 200
    assert b"v9.9.9-test" in resp.data
    assert f"v{__version__}".encode() not in resp.data
