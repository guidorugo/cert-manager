"""Tests for LDAP authentication (Phase 1: session login).

ldap3 is mocked at the module boundary: ldap_service calls
ldap3.Connection(...), so tests monkeypatch ldap3.Connection with fakes.
No directory server is needed.
"""
import json
import re
from types import SimpleNamespace

import ldap3
import pytest
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

from app import create_app
from app.config import Config
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services import auth_service, ldap_service


BASE_LDAP_CONFIG = {
    "LDAP_ENABLED": True,
    "LDAP_SERVER_URI": "ldaps://ldap.test:636",
    "LDAP_USER_DN_TEMPLATE": "uid={username},ou=people,dc=test",
    "LDAP_USER_SEARCH_BASE": "",
    "LDAP_BIND_DN": "",
    "LDAP_BIND_PASSWORD": "",
    "LDAP_ADMIN_GROUP_DN": "cn=cert-admins,ou=groups,dc=test",
    "LDAP_REQUESTER_GROUP_DN": "cn=cert-requesters,ou=groups,dc=test",
}

DIRECTORY = {
    "uid=alice,ou=people,dc=test": {
        "password": "alice-pw",
        "uid": "alice",
        "memberOf": ["cn=cert-admins,ou=groups,dc=test"],
    },
    "uid=bob,ou=people,dc=test": {
        "password": "bob-pw",
        "uid": "bob",
        "memberOf": ["cn=cert-requesters,ou=groups,dc=test"],
    },
    "uid=carol,ou=people,dc=test": {
        "password": "carol-pw",
        "uid": "carol",
        "memberOf": [],
    },
    "cn=svc,ou=services,dc=test": {"password": "svc-pw", "memberOf": []},
}


class FakeEntry:
    def __init__(self, dn, attrs):
        self.entry_dn = dn
        self._attrs = attrs

    def __getitem__(self, key):
        if key not in self._attrs:
            raise KeyError(key)
        return SimpleNamespace(values=list(self._attrs[key]))


class FakeConnection:
    """Emulates the slice of the ldap3 Connection API that ldap_service uses."""

    last_search_filter = None  # records the most recent search filter

    def __init__(self, server, user=None, password=None, auto_bind=None, **kwargs):
        entry = DIRECTORY.get(user)
        if entry is None or entry["password"] != password:
            raise LDAPBindError("automatic bind not successful - invalidCredentials")
        self.bound_dn = user
        self.entries = []

    def search(self, search_base, search_filter, search_scope=None, attributes=None, **kwargs):
        FakeConnection.last_search_filter = search_filter
        self.entries = []
        if search_scope == ldap3.BASE and search_base in DIRECTORY:
            self.entries = [FakeEntry(search_base, DIRECTORY[search_base])]
            return True
        match = re.fullmatch(r"\(uid=([^)]*)\)", search_filter)
        if match:
            uid = match.group(1)
            for dn, attrs in DIRECTORY.items():
                if attrs.get("uid") == uid and dn.endswith(search_base):
                    self.entries.append(FakeEntry(dn, attrs))
        return bool(self.entries)

    def unbind(self):
        return True


def _forbid_ldap(*args, **kwargs):
    raise AssertionError("LDAP must not be contacted in this scenario")


def _ldap_down(*args, **kwargs):
    raise LDAPSocketOpenError("connection refused")


def _authenticate(app, username, password):
    """Call auth_service.authenticate inside a request context.

    audit_service.log_action reads request/current_user, so authenticate()
    must run in a request context — as it always does in production.
    """
    with app.test_request_context():
        return auth_service.authenticate(username, password)


@pytest.fixture
def ldap_app(app, monkeypatch):
    for key, value in BASE_LDAP_CONFIG.items():
        monkeypatch.setitem(app.config, key, value)
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)
    return app


@pytest.fixture
def search_mode(ldap_app, monkeypatch):
    monkeypatch.setitem(ldap_app.config, "LDAP_USER_DN_TEMPLATE", "")
    monkeypatch.setitem(ldap_app.config, "LDAP_USER_SEARCH_BASE", "ou=people,dc=test")
    monkeypatch.setitem(ldap_app.config, "LDAP_BIND_DN", "cn=svc,ou=services,dc=test")
    monkeypatch.setitem(ldap_app.config, "LDAP_BIND_PASSWORD", "svc-pw")
    return ldap_app


class TestLdapService:
    def test_empty_password_rejected_before_bind(self, ldap_app, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _forbid_ldap)
        assert ldap_service.authenticate_ldap("alice", "") is None
        assert ldap_service.authenticate_ldap("alice", "   ") is None
        assert ldap_service.authenticate_ldap("", "x") is None

    def test_template_bind_success_returns_dn_and_groups(self, ldap_app):
        result = ldap_service.authenticate_ldap("alice", "alice-pw")
        assert result is not None
        assert result.dn == "uid=alice,ou=people,dc=test"
        assert "cn=cert-admins,ou=groups,dc=test" in result.groups

    def test_wrong_password_returns_none(self, ldap_app):
        assert ldap_service.authenticate_ldap("alice", "wrong") is None

    def test_unknown_user_returns_none(self, ldap_app):
        assert ldap_service.authenticate_ldap("mallory", "x") is None

    def test_server_down_raises_unavailable(self, ldap_app, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        with pytest.raises(ldap_service.LdapUnavailableError):
            ldap_service.authenticate_ldap("alice", "alice-pw")

    def test_search_mode_finds_dn_and_groups(self, search_mode):
        result = ldap_service.authenticate_ldap("bob", "bob-pw")
        assert result is not None
        assert result.dn == "uid=bob,ou=people,dc=test"
        assert "cn=cert-requesters,ou=groups,dc=test" in result.groups

    def test_search_mode_wrong_password(self, search_mode):
        assert ldap_service.authenticate_ldap("bob", "wrong") is None

    def test_search_filter_escapes_injection(self, search_mode):
        assert ldap_service.authenticate_ldap("alice)(uid=*", "x") is None
        assert "\\29" in FakeConnection.last_search_filter  # ')' escaped
        assert "\\2a" in FakeConnection.last_search_filter  # '*' escaped


class TestAuthService:
    def test_local_admin_never_touches_ldap(self, ldap_app, admin_user, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _forbid_ldap)
        result = _authenticate(ldap_app, "testadmin", "adminpass")
        assert result.ok
        assert result.auth_method == "local"

    def test_local_wrong_password_does_not_fall_through_to_ldap(
        self, ldap_app, admin_user, monkeypatch
    ):
        monkeypatch.setattr(ldap3, "Connection", _forbid_ldap)
        result = _authenticate(ldap_app, "testadmin", "wrong")
        assert not result.ok
        assert result.reason == auth_service.REASON_INVALID

    def test_ldap_login_provisions_admin(self, ldap_app, db):
        result = _authenticate(ldap_app, "alice", "alice-pw")
        assert result.ok
        assert result.auth_method == "ldap"
        user = User.query.filter_by(username="alice").one()
        assert user.role == "admin"
        assert user.auth_source == "ldap"
        assert not user.has_usable_password()

    def test_ldap_login_provisions_requester(self, ldap_app, db):
        result = _authenticate(ldap_app, "bob", "bob-pw")
        assert result.ok
        assert result.user.role == "csr_requester"

    def test_provisioning_happens_once(self, ldap_app, db):
        first = _authenticate(ldap_app, "bob", "bob-pw")
        db.session.commit()
        second = _authenticate(ldap_app, "bob", "bob-pw")
        db.session.commit()
        assert first.ok and second.ok
        assert User.query.filter_by(username="bob").count() == 1

    def test_role_resynced_on_login(self, ldap_app, db):
        user = User(username="bob", role="admin", auth_source="ldap")
        user.set_unusable_password()
        db.session.add(user)
        db.session.commit()

        result = _authenticate(ldap_app, "bob", "bob-pw")
        assert result.ok
        assert result.user.role == "csr_requester"
        entry = AuditLog.query.filter_by(action="ldap_role_synced").first()
        assert entry is not None

    def test_user_in_no_mapped_group_rejected(self, ldap_app, db):
        result = _authenticate(ldap_app, "carol", "carol-pw")
        assert not result.ok
        assert result.reason == auth_service.REASON_LDAP_NO_ROLE
        assert User.query.filter_by(username="carol").count() == 0

    def test_no_group_config_defaults_to_requester(self, ldap_app, db, monkeypatch):
        monkeypatch.setitem(ldap_app.config, "LDAP_ADMIN_GROUP_DN", "")
        monkeypatch.setitem(ldap_app.config, "LDAP_REQUESTER_GROUP_DN", "")
        result = _authenticate(ldap_app, "carol", "carol-pw")
        assert result.ok
        assert result.user.role == "csr_requester"

    def test_locally_deactivated_ldap_user_rejected(self, ldap_app, db):
        user = User(username="alice", role="admin", auth_source="ldap", is_active_user=False)
        user.set_unusable_password()
        db.session.add(user)
        db.session.commit()

        result = _authenticate(ldap_app, "alice", "alice-pw")
        assert not result.ok
        assert result.reason == auth_service.REASON_DEACTIVATED

    def test_ldap_down_reported(self, ldap_app, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        result = _authenticate(ldap_app, "alice", "alice-pw")
        assert not result.ok
        assert result.reason == auth_service.REASON_LDAP_UNREACHABLE

    def test_ldap_down_local_admin_still_works(self, ldap_app, admin_user, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        result = _authenticate(ldap_app, "testadmin", "adminpass")
        assert result.ok

    def test_ldap_user_rejected_when_ldap_disabled(self, app, db, monkeypatch):
        monkeypatch.setitem(app.config, "LDAP_ENABLED", False)
        user = User(username="dave", role="csr_requester", auth_source="ldap")
        user.set_unusable_password()
        db.session.add(user)
        db.session.commit()

        result = _authenticate(app, "dave", "anything")
        assert not result.ok
        assert result.reason == auth_service.REASON_INVALID


class TestUnusablePassword:
    def test_check_password_always_false(self, db):
        user = User(username="ldapuser", role="csr_requester", auth_source="ldap")
        user.set_unusable_password()
        db.session.add(user)
        db.session.commit()
        assert user.has_usable_password() is False
        assert user.check_password("anything") is False
        assert user.check_password("!") is False

    def test_basic_auth_rejected_for_ldap_user_when_ldap_disabled(self, client, db):
        import base64

        user = User(username="ldapuser", role="csr_requester", auth_source="ldap")
        user.set_unusable_password()
        db.session.add(user)
        db.session.commit()
        creds = base64.b64encode(b"ldapuser:anything").decode()
        resp = client.get("/csr/", headers={"Authorization": f"Basic {creds}"})
        assert resp.status_code == 401


class TestLdapLoginRoute:
    def test_login_via_ldap_redirects_and_provisions(self, ldap_app, client, db):
        resp = client.post(
            "/auth/login",
            data={"username": "alice", "password": "alice-pw"},
            follow_redirects=False,
        )
        assert resp.status_code == 302

        user = User.query.filter_by(username="alice").one()
        assert user.auth_source == "ldap"

        entry = AuditLog.query.filter_by(action="login_success").first()
        assert entry is not None
        assert json.loads(entry.details)["auth_method"] == "ldap"
        assert AuditLog.query.filter_by(action="ldap_user_provisioned").first() is not None

    def test_ldap_down_shows_directory_message(self, ldap_app, client, monkeypatch):
        monkeypatch.setattr(ldap3, "Connection", _ldap_down)
        resp = client.post(
            "/auth/login", data={"username": "alice", "password": "alice-pw"}
        )
        assert b"Directory service is unavailable" in resp.data

    def test_wrong_ldap_password_shows_generic_message(self, ldap_app, client):
        resp = client.post(
            "/auth/login", data={"username": "alice", "password": "nope"}
        )
        assert b"Invalid username or password." in resp.data

    def test_no_role_shows_generic_message(self, ldap_app, client):
        """Group-mapping failures must not reveal that the password was valid."""
        resp = client.post(
            "/auth/login", data={"username": "carol", "password": "carol-pw"}
        )
        assert b"Invalid username or password." in resp.data
        entry = AuditLog.query.filter_by(action="login_failure").first()
        assert json.loads(entry.details)["reason"] == "ldap_no_role"


class TestLdapConfigValidation:
    @staticmethod
    def _base_config():
        class LdapTestConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = "sqlite://"
            SECRET_KEY = "test-secret"
            MASTER_PASSPHRASE = "test-passphrase"
            WTF_CSRF_ENABLED = False
            LDAP_ENABLED = True
            LDAP_SERVER_URI = "ldaps://ldap.test:636"
            LDAP_USER_DN_TEMPLATE = "uid={username},ou=people,dc=test"
            LDAP_USER_SEARCH_BASE = ""
            LDAP_BIND_DN = ""
            LDAP_BIND_PASSWORD = ""

        return LdapTestConfig

    def test_missing_server_uri_exits(self):
        cfg = self._base_config()
        cfg.LDAP_SERVER_URI = ""
        with pytest.raises(SystemExit):
            create_app(cfg)

    def test_template_and_search_both_set_exits(self):
        cfg = self._base_config()
        cfg.LDAP_USER_SEARCH_BASE = "ou=people,dc=test"
        with pytest.raises(SystemExit):
            create_app(cfg)

    def test_neither_mode_configured_exits(self):
        cfg = self._base_config()
        cfg.LDAP_USER_DN_TEMPLATE = ""
        with pytest.raises(SystemExit):
            create_app(cfg)

    def test_template_without_placeholder_exits(self):
        cfg = self._base_config()
        cfg.LDAP_USER_DN_TEMPLATE = "uid=admin,dc=test"
        with pytest.raises(SystemExit):
            create_app(cfg)

    def test_search_mode_requires_bind_credentials(self):
        cfg = self._base_config()
        cfg.LDAP_USER_DN_TEMPLATE = ""
        cfg.LDAP_USER_SEARCH_BASE = "ou=people,dc=test"
        with pytest.raises(SystemExit):
            create_app(cfg)

    def test_valid_template_config_boots(self):
        app = create_app(self._base_config())
        assert app is not None


class TestLdapConfigEnvHardening:
    def test_empty_env_strings_fall_back_to_defaults(self, monkeypatch):
        """docker-compose passes unset variables as empty strings; empty
        must behave exactly like unset for vars with non-empty defaults
        (an empty LDAP_TLS_VERIFY silently disabling TLS verification
        would be a security bug; int("") would crash at import)."""
        import importlib

        import app.config as config_module

        monkeypatch.setenv("LDAP_USER_FILTER", "")
        monkeypatch.setenv("LDAP_GROUP_MEMBER_ATTR", "")
        monkeypatch.setenv("LDAP_TIMEOUT_SECONDS", "")
        monkeypatch.setenv("LDAP_TLS_VERIFY", "")
        monkeypatch.setenv("BASIC_AUTH_CACHE_TTL_SECONDS", "")
        try:
            reloaded = importlib.reload(config_module)
            assert reloaded.Config.LDAP_USER_FILTER == "(uid={username})"
            assert reloaded.Config.LDAP_GROUP_MEMBER_ATTR == "memberOf"
            assert reloaded.Config.LDAP_TIMEOUT_SECONDS == 5
            assert reloaded.Config.LDAP_TLS_VERIFY is True
            assert reloaded.Config.BASIC_AUTH_CACHE_TTL_SECONDS == 60
        finally:
            monkeypatch.undo()
            importlib.reload(config_module)
