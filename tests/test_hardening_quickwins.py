"""Hardening quick-wins batch (F2, E3, D5, F3)."""
from types import SimpleNamespace

import pytest

from app import _check_security, _validate_ldap_config, _create_default_admin
from app.config import Config
from app.services import ca_service, crl_service
from app.models.user import User

PASSPHRASE = "test-passphrase"


def _ldap_cfg(**over):
    cfg = {
        "LDAP_ENABLED": True,
        "LDAP_SERVER_URI": "ldap://dc.example.com",
        "LDAP_USER_DN_TEMPLATE": "uid={username},dc=example,dc=com",
        "LDAP_USE_STARTTLS": False,
        "LDAP_ALLOW_PLAINTEXT": False,
    }
    cfg.update(over)
    return SimpleNamespace(config=cfg)


# --- E3: LDAP plaintext guardrail -------------------------------------------

def test_ldap_plaintext_refused():
    with pytest.raises(SystemExit):
        _validate_ldap_config(_ldap_cfg())


def test_ldap_plaintext_allowed_with_explicit_flag():
    _validate_ldap_config(_ldap_cfg(LDAP_ALLOW_PLAINTEXT=True))  # no exit


def test_ldaps_uri_ok():
    _validate_ldap_config(_ldap_cfg(LDAP_SERVER_URI="ldaps://dc.example.com"))


def test_ldap_starttls_ok():
    _validate_ldap_config(_ldap_cfg(LDAP_USE_STARTTLS=True))


def test_ldap_failover_one_plaintext_refused():
    # a mixed comma-separated list with any cleartext member is refused
    with pytest.raises(SystemExit):
        _validate_ldap_config(_ldap_cfg(
            LDAP_SERVER_URI="ldaps://a.example.com, ldap://b.example.com"))


# --- F2: debug mode is loud, not silent -------------------------------------

def test_check_security_debug_warns_not_exit(capsys):
    app = SimpleNamespace(debug=True, config={"TESTING": False})
    _check_security(app)  # must not exit
    assert "debug mode is ON" in capsys.readouterr().err


def test_check_security_prod_insecure_exits():
    app = SimpleNamespace(debug=False, config={
        "TESTING": False,
        "SECRET_KEY": Config._INSECURE_SECRET_KEY,
        "MASTER_PASSPHRASE": "whatever",
        "ADMIN_PASSWORD": "whatever",
    })
    with pytest.raises(SystemExit):
        _check_security(app)


# --- D5: default-admin seeding is safe when users already exist -------------

def test_create_default_admin_skips_when_users_exist(app, db):
    with app.app_context():
        u = User(username="existing", role="admin")
        u.set_password("x")
        db.session.add(u)
        db.session.commit()
        before = User.query.count()
        _create_default_admin(app)  # must not add a second seed or raise
        assert User.query.count() == before


# --- F3: CRL numbers are monotonic ------------------------------------------

def test_crl_number_monotonic(app, db):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="CRLNum Root", subject_attrs={"CN": "CRLNum Root"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE,
        )
        n0 = ca.crl_number  # initial CRL published at creation
        crl_service.generate_crl(ca, PASSPHRASE)
        n1 = ca.crl_number
        crl_service.generate_crl(ca, PASSPHRASE)
        n2 = ca.crl_number
        assert n1 == n0 + 1
        assert n2 == n1 + 1
