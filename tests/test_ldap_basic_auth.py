"""Tests for LDAP over HTTP Basic Auth (Phase 2) and the credential cache."""
import base64
import json
import time

import ldap3
import pytest

from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.auth_service import CredentialCache

from tests.test_ldap import BASE_LDAP_CONFIG, FakeConnection, _ldap_down


def _basic(username, password):
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


class CountingConnection(FakeConnection):
    """FakeConnection that counts constructions (= LDAP binds attempted)."""

    constructed = 0

    def __init__(self, *args, **kwargs):
        CountingConnection.constructed += 1
        super().__init__(*args, **kwargs)


@pytest.fixture
def ldap_basic_app(app, monkeypatch):
    for key, value in BASE_LDAP_CONFIG.items():
        monkeypatch.setitem(app.config, key, value)
    CountingConnection.constructed = 0
    monkeypatch.setattr(ldap3, "Connection", CountingConnection)
    monkeypatch.setattr(app, "basic_auth_cache", CredentialCache(60))
    return app


class TestLdapBasicAuth:
    def test_ldap_admin_reaches_admin_route(self, ldap_basic_app, client, db):
        resp = client.get("/ca/", headers=_basic("alice", "alice-pw"))
        assert resp.status_code == 200
        user = User.query.filter_by(username="alice").one()
        assert user.auth_source == "ldap"
        assert user.role == "admin"

    def test_ldap_requester_role_enforced(self, ldap_basic_app, client, db):
        assert client.get("/csr/", headers=_basic("bob", "bob-pw")).status_code == 200
        assert client.get("/ca/", headers=_basic("bob", "bob-pw")).status_code == 403

    def test_wrong_password_rejected(self, ldap_basic_app, client, db):
        resp = client.get("/ca/", headers=_basic("alice", "wrong"))
        assert resp.status_code == 401

    def test_empty_password_rejected_without_bind(self, ldap_basic_app, client, db):
        resp = client.get("/ca/", headers=_basic("alice", ""))
        assert resp.status_code == 401
        assert CountingConnection.constructed == 0

    def test_local_user_unaffected(self, ldap_basic_app, client, admin_user, db):
        resp = client.get("/ca/", headers=_basic("testadmin", "adminpass"))
        assert resp.status_code == 200
        assert CountingConnection.constructed == 0
        entry = AuditLog.query.filter_by(action="basic_auth_success").first()
        assert json.loads(entry.details)["auth_backend"] == "local"

    def test_audit_records_ldap_backend(self, ldap_basic_app, client, db):
        client.get("/csr/", headers=_basic("bob", "bob-pw"))
        entry = AuditLog.query.filter_by(action="basic_auth_success").first()
        assert json.loads(entry.details)["auth_backend"] == "ldap"


class TestBasicAuthCredentialCache:
    def test_cache_skips_repeat_ldap_binds(self, ldap_basic_app, client, db):
        assert client.get("/ca/", headers=_basic("alice", "alice-pw")).status_code == 200
        first = CountingConnection.constructed
        assert first >= 1
        assert client.get("/ca/", headers=_basic("alice", "alice-pw")).status_code == 200
        assert CountingConnection.constructed == first  # served from cache

    def test_zero_ttl_disables_cache(self, ldap_basic_app, client, db, monkeypatch):
        monkeypatch.setattr(ldap_basic_app, "basic_auth_cache", CredentialCache(0))
        client.get("/ca/", headers=_basic("alice", "alice-pw"))
        first = CountingConnection.constructed
        client.get("/ca/", headers=_basic("alice", "alice-pw"))
        assert CountingConnection.constructed == 2 * first  # full auth both times

    def test_wrong_password_never_served_from_cache(self, ldap_basic_app, client, db):
        assert client.get("/ca/", headers=_basic("alice", "alice-pw")).status_code == 200
        before = CountingConnection.constructed
        resp = client.get("/ca/", headers=_basic("alice", "wrong"))
        assert resp.status_code == 401
        assert CountingConnection.constructed > before  # took the full path

    def test_deactivation_applies_within_ttl(self, ldap_basic_app, client, db):
        assert client.get("/ca/", headers=_basic("alice", "alice-pw")).status_code == 200
        user = User.query.filter_by(username="alice").one()
        user.is_active_user = False
        db.session.commit()
        resp = client.get("/ca/", headers=_basic("alice", "alice-pw"))
        assert resp.status_code == 401

    def test_cached_credentials_survive_directory_outage(self, ldap_basic_app, client, db, monkeypatch):
        assert client.get("/ca/", headers=_basic("alice", "alice-pw")).status_code == 200
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        assert client.get("/ca/", headers=_basic("alice", "alice-pw")).status_code == 200

    def test_directory_outage_returns_503_when_not_cached(self, ldap_basic_app, client, db, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        resp = client.get("/ca/", headers=_basic("alice", "alice-pw"))
        assert resp.status_code == 503
        assert resp.get_json()["error"] == "Directory service unavailable."
        entry = AuditLog.query.filter_by(action="basic_auth_failed").first()
        assert json.loads(entry.details)["reason"] == "ldap_unreachable"

    def test_outage_does_not_affect_local_users(self, ldap_basic_app, client, admin_user, db, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        resp = client.get("/ca/", headers=_basic("testadmin", "adminpass"))
        assert resp.status_code == 200


class TestCredentialCacheUnit:
    def test_roundtrip(self):
        cache = CredentialCache(60)
        cache.put("u", "p", 7, "ldap")
        assert cache.get("u", "p") == (7, "ldap")

    def test_wrong_password_misses_but_keeps_entry(self):
        cache = CredentialCache(60)
        cache.put("u", "p", 7, "ldap")
        assert cache.get("u", "wrong") is None
        assert cache.get("u", "p") == (7, "ldap")

    def test_unknown_user_misses(self):
        cache = CredentialCache(60)
        assert cache.get("nobody", "x") is None

    def test_entries_expire(self):
        cache = CredentialCache(0.05)
        cache.put("u", "p", 7, "local")
        time.sleep(0.1)
        assert cache.get("u", "p") is None

    def test_zero_ttl_disables(self):
        cache = CredentialCache(0)
        cache.put("u", "p", 7, "local")
        assert cache.get("u", "p") is None

    def test_max_entries_evicts_oldest(self):
        cache = CredentialCache(60, max_entries=2)
        cache.put("u1", "p1", 1, "local")
        cache.put("u2", "p2", 2, "local")
        cache.put("u3", "p3", 3, "local")
        assert len(cache._entries) == 2
        assert cache.get("u1", "p1") is None  # oldest evicted
        assert cache.get("u3", "p3") == (3, "local")

    def test_clear(self):
        cache = CredentialCache(60)
        cache.put("u", "p", 7, "local")
        cache.clear()
        assert cache.get("u", "p") is None
