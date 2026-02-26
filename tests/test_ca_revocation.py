import pytest

from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.models.certificate import Certificate
from app.services import ca_service, cert_service, crl_service


PASSPHRASE = "test-passphrase"


def _create_root_ca(name="Test Root CA"):
    return ca_service.create_root_ca(
        name=name,
        subject_attrs={"CN": name},
        key_type="RSA",
        key_size=2048,
        validity_days=3650,
        passphrase=PASSPHRASE,
    )


def _create_intermediate_ca(parent, name="Test Intermediate CA"):
    return ca_service.create_intermediate_ca(
        name=name,
        parent_ca=parent,
        subject_attrs={"CN": name},
        key_type="RSA",
        key_size=2048,
        validity_days=1825,
        passphrase=PASSPHRASE,
    )


def _create_cert(ca, cn="test.example.com"):
    return cert_service.create_certificate(
        ca=ca,
        subject_attrs={"CN": cn},
        san_list=[cn],
        validity_days=365,
        passphrase=PASSPHRASE,
        key_type="RSA",
        key_size=2048,
    )


class TestCaRevocationService:
    """Tests for the revoke_ca() service function."""

    def test_revoke_ca_marks_as_revoked(self, app, db):
        with app.app_context():
            ca = _create_root_ca()
            revoked_ca, certs_revoked, sub_cas_revoked = crl_service.revoke_ca(ca.id)

            assert revoked_ca.is_revoked is True
            assert revoked_ca.revoked_at is not None
            assert revoked_ca.revocation_reason == "unspecified"
            assert certs_revoked == 0
            assert sub_cas_revoked == 0

    def test_revoke_ca_with_reason(self, app, db):
        with app.app_context():
            ca = _create_root_ca()
            revoked_ca, _, _ = crl_service.revoke_ca(ca.id, reason="key_compromise")

            assert revoked_ca.revocation_reason == "key_compromise"

    def test_revoke_ca_cascades_to_certificates(self, app, db):
        with app.app_context():
            ca = _create_root_ca()
            cert1 = _create_cert(ca, "cert1.example.com")
            cert2 = _create_cert(ca, "cert2.example.com")

            _, certs_revoked, _ = crl_service.revoke_ca(ca.id)

            assert certs_revoked == 2
            assert db.session.get(Certificate, cert1.id).is_revoked is True
            assert db.session.get(Certificate, cert2.id).is_revoked is True

    def test_revoke_ca_skips_already_revoked_certs(self, app, db):
        with app.app_context():
            ca = _create_root_ca()
            _create_cert(ca, "active.example.com")
            crl_service.revoke_certificate(
                _create_cert(ca, "already-revoked.example.com").id
            )

            _, certs_revoked, _ = crl_service.revoke_ca(ca.id)

            assert certs_revoked == 1  # only the active one

    def test_revoke_ca_cascades_to_sub_cas(self, app, db):
        with app.app_context():
            root = _create_root_ca()
            child = _create_intermediate_ca(root, "Child CA")
            _create_cert(child, "child-cert.example.com")

            _, certs_revoked, sub_cas_revoked = crl_service.revoke_ca(root.id)

            assert sub_cas_revoked == 1
            assert certs_revoked == 1
            child_db = db.session.get(CertificateAuthority, child.id)
            assert child_db.is_revoked is True

    def test_revoke_ca_cascades_recursively(self, app, db):
        with app.app_context():
            root = _create_root_ca()
            child = _create_intermediate_ca(root, "Child CA")
            grandchild = _create_intermediate_ca(child, "Grandchild CA")
            _create_cert(grandchild, "deep.example.com")

            _, certs_revoked, sub_cas_revoked = crl_service.revoke_ca(root.id)

            assert sub_cas_revoked == 2
            assert certs_revoked == 1
            assert db.session.get(CertificateAuthority, child.id).is_revoked is True
            assert db.session.get(CertificateAuthority, grandchild.id).is_revoked is True

    def test_revoke_already_revoked_ca_raises(self, app, db):
        with app.app_context():
            ca = _create_root_ca()
            crl_service.revoke_ca(ca.id)

            with pytest.raises(ValueError, match="already revoked"):
                crl_service.revoke_ca(ca.id)

    def test_revoke_nonexistent_ca_raises(self, app, db):
        with app.app_context():
            with pytest.raises(ValueError, match="not found"):
                crl_service.revoke_ca(99999)


class TestCaRevocationRoute:
    """Tests for the CA revoke route."""

    def test_revoke_page_renders(self, auth_admin, app, db):
        with app.app_context():
            ca = _create_root_ca()
            ca_id = ca.id
        resp = auth_admin.get(f"/ca/{ca_id}/revoke")
        assert resp.status_code == 200
        assert b"Revoke Certificate Authority" in resp.data

    def test_revoke_post_revokes_ca(self, auth_admin, app, db):
        with app.app_context():
            ca = _create_root_ca()
            ca_id = ca.id
        resp = auth_admin.post(f"/ca/{ca_id}/revoke", data={"reason": "key_compromise"})
        assert resp.status_code == 302
        with app.app_context():
            ca_db = db.session.get(CertificateAuthority, ca_id)
            assert ca_db.is_revoked is True
            assert ca_db.revocation_reason == "key_compromise"

    def test_revoke_already_revoked_redirects(self, auth_admin, app, db):
        with app.app_context():
            ca = _create_root_ca()
            ca_id = ca.id
            crl_service.revoke_ca(ca_id)
        resp = auth_admin.get(f"/ca/{ca_id}/revoke")
        assert resp.status_code == 302  # redirect

    def test_revoke_audit_logged(self, auth_admin, app, db):
        with app.app_context():
            ca = _create_root_ca()
            ca_id = ca.id
        auth_admin.post(f"/ca/{ca_id}/revoke", data={"reason": "superseded"})
        with app.app_context():
            entry = AuditLog.query.filter_by(action="revoke_ca").first()
            assert entry is not None
            assert entry.target_type == "ca"


class TestCaRevocationGuards:
    """Tests for guards that prevent operations on revoked CAs."""

    def test_cannot_generate_crl_for_revoked_ca(self, auth_admin, app, db):
        with app.app_context():
            ca = _create_root_ca()
            ca_id = ca.id
            crl_service.revoke_ca(ca_id)
        resp = auth_admin.post(f"/ca/{ca_id}/crl")
        assert resp.status_code == 302
        # Follow redirect and check flash message
        resp2 = auth_admin.get(f"/ca/{ca_id}")
        assert b"Cannot generate CRL for a revoked CA" in resp2.data

    def test_cannot_issue_cert_from_revoked_ca(self, auth_admin, app, db):
        with app.app_context():
            ca = _create_root_ca()
            ca_id = ca.id
            crl_service.revoke_ca(ca_id)
        resp = auth_admin.post("/certificates/create", data={
            "ca_id": ca_id,
            "cn": "should-fail.example.com",
            "key_type": "RSA",
            "key_size": "2048",
            "validity_days": "365",
        })
        assert b"Cannot issue certificates from a revoked CA" in resp.data

    def test_cannot_sign_csr_with_revoked_ca(self, auth_admin, app, db):
        with app.app_context():
            ca = _create_root_ca()
            ca_id = ca.id
            from app.services import csr_service
            csr_model, _, _ = csr_service.create_csr(
                subject_attrs={"CN": "test-csr.example.com"},
                san_list=["test-csr.example.com"],
                key_type="RSA",
                key_size=2048,
                passphrase=PASSPHRASE,
            )
            db.session.commit()
            csr_id = csr_model.id
            crl_service.revoke_ca(ca_id)
        resp = auth_admin.post(f"/csr/{csr_id}/sign", data={
            "ca_id": ca_id,
            "validity_days": "365",
        })
        assert b"Cannot sign CSR with a revoked CA" in resp.data
