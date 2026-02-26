import pytest

from app.extensions import db
from app.models.user import User
from app.models.csr import CertificateSigningRequest


class TestAdminRouteAccess:
    """Admin users can access admin-only routes."""

    def test_admin_can_access_ca_list(self, auth_admin):
        resp = auth_admin.get("/ca/")
        assert resp.status_code == 200

    def test_admin_can_access_certificates_list(self, auth_admin):
        resp = auth_admin.get("/certificates/")
        assert resp.status_code == 200

    def test_admin_can_access_users_list(self, auth_admin):
        resp = auth_admin.get("/users/")
        assert resp.status_code == 200

    def test_csr_requester_redirected_from_ca(self, auth_csr_requester):
        resp = auth_csr_requester.get("/ca/", follow_redirects=True)
        assert b"do not have permission" in resp.data

    def test_csr_requester_redirected_from_users(self, auth_csr_requester):
        resp = auth_csr_requester.get("/users/", follow_redirects=True)
        assert b"do not have permission" in resp.data


class TestCSRRequesterAccess:
    """CSR requesters can access CSR and certificate routes but not sign/reject."""

    def test_can_access_csr_list(self, auth_csr_requester):
        resp = auth_csr_requester.get("/csr/")
        assert resp.status_code == 200

    def test_can_access_csr_create(self, auth_csr_requester):
        resp = auth_csr_requester.get("/csr/create")
        assert resp.status_code == 200

    def test_can_access_certificates_list(self, auth_csr_requester):
        resp = auth_csr_requester.get("/certificates/")
        assert resp.status_code == 200

    def test_cannot_sign_csr(self, auth_csr_requester, db):
        csr = CertificateSigningRequest(
            common_name="test",
            subject_json='{"CN": "test"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            status="pending",
        )
        db.session.add(csr)
        db.session.commit()

        resp = auth_csr_requester.get(f"/csr/{csr.id}/sign", follow_redirects=True)
        assert b"do not have permission" in resp.data

    def test_cannot_reject_csr(self, auth_csr_requester, db):
        csr = CertificateSigningRequest(
            common_name="test",
            subject_json='{"CN": "test"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            status="pending",
        )
        db.session.add(csr)
        db.session.commit()

        resp = auth_csr_requester.post(f"/csr/{csr.id}/reject", follow_redirects=True)
        assert b"do not have permission" in resp.data


class TestCSROwnership:
    """CSR requesters can only view their own CSRs."""

    def test_cannot_view_others_csr(self, auth_csr_requester, admin_user, csr_requester, db):
        csr = CertificateSigningRequest(
            common_name="admin-csr",
            subject_json='{"CN": "admin-csr"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            created_by=admin_user.id,
        )
        db.session.add(csr)
        db.session.commit()

        resp = auth_csr_requester.get(f"/csr/{csr.id}", follow_redirects=True)
        assert b"do not have permission" in resp.data

    def test_can_view_own_csr(self, auth_csr_requester, csr_requester, db):
        csr = CertificateSigningRequest(
            common_name="my-csr",
            subject_json='{"CN": "my-csr"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
            created_by=csr_requester.id,
        )
        db.session.add(csr)
        db.session.commit()

        resp = auth_csr_requester.get(f"/csr/{csr.id}")
        assert resp.status_code == 200

    def test_list_only_shows_own(self, auth_csr_requester, admin_user, csr_requester, db):
        csr_own = CertificateSigningRequest(
            common_name="own-csr",
            subject_json='{"CN": "own-csr"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\nown\n-----END CERTIFICATE REQUEST-----",
            created_by=csr_requester.id,
        )
        csr_other = CertificateSigningRequest(
            common_name="other-csr",
            subject_json='{"CN": "other-csr"}',
            csr_pem="-----BEGIN CERTIFICATE REQUEST-----\nother\n-----END CERTIFICATE REQUEST-----",
            created_by=admin_user.id,
        )
        db.session.add_all([csr_own, csr_other])
        db.session.commit()

        resp = auth_csr_requester.get("/csr/")
        assert b"own-csr" in resp.data
        assert b"other-csr" not in resp.data


class TestCertificateOwnership:
    """CSR requesters can only view their own certificates."""

    def test_can_view_own_certificate(self, auth_csr_requester, csr_requester, db):
        from app.models.certificate import Certificate
        from datetime import datetime, timezone
        cert = Certificate(
            serial_number="abc123",
            common_name="my-cert",
            subject_json='{"CN": "my-cert"}',
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            ca_id=1,
            key_type="RSA",
            key_size=2048,
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
            requested_by=csr_requester.id,
        )
        db.session.add(cert)
        db.session.commit()

        resp = auth_csr_requester.get(f"/certificates/{cert.id}")
        assert resp.status_code == 200

    def test_cannot_view_others_certificate(self, auth_csr_requester, admin_user, db):
        from app.models.certificate import Certificate
        from datetime import datetime, timezone
        cert = Certificate(
            serial_number="def456",
            common_name="admin-cert",
            subject_json='{"CN": "admin-cert"}',
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            ca_id=1,
            key_type="RSA",
            key_size=2048,
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
            requested_by=admin_user.id,
        )
        db.session.add(cert)
        db.session.commit()

        resp = auth_csr_requester.get(f"/certificates/{cert.id}", follow_redirects=True)
        assert b"do not have permission" in resp.data

    def test_cert_list_only_shows_own(self, auth_csr_requester, admin_user, csr_requester, db):
        from app.models.certificate import Certificate
        from datetime import datetime, timezone
        cert_own = Certificate(
            serial_number="own111",
            common_name="own-cert",
            subject_json='{"CN": "own-cert"}',
            certificate_pem="-----BEGIN CERTIFICATE-----\nown\n-----END CERTIFICATE-----",
            ca_id=1, key_type="RSA", key_size=2048,
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
            requested_by=csr_requester.id,
        )
        cert_other = Certificate(
            serial_number="other222",
            common_name="other-cert",
            subject_json='{"CN": "other-cert"}',
            certificate_pem="-----BEGIN CERTIFICATE-----\nother\n-----END CERTIFICATE-----",
            ca_id=1, key_type="RSA", key_size=2048,
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
            requested_by=admin_user.id,
        )
        db.session.add_all([cert_own, cert_other])
        db.session.commit()

        resp = auth_csr_requester.get("/certificates/")
        assert b"own-cert" in resp.data
        assert b"other-cert" not in resp.data


class TestDeactivatedUser:
    """Deactivated users cannot login."""

    def test_deactivated_user_login_rejected(self, client, db):
        user = User(username="inactive", role="admin", is_active_user=False)
        user.set_password("password")
        db.session.add(user)
        db.session.commit()

        resp = client.post("/auth/login", data={
            "username": "inactive",
            "password": "password",
        }, follow_redirects=True)
        assert b"deactivated" in resp.data


class TestLastAdminProtection:
    """Cannot deactivate or demote the last active admin."""

    def test_cannot_deactivate_last_admin(self, auth_admin, admin_user, db):
        resp = auth_admin.post(
            f"/users/{admin_user.id}/toggle-active",
            follow_redirects=True,
        )
        assert b"cannot deactivate your own account" in resp.data.lower()

    def test_cannot_demote_last_admin(self, auth_admin, admin_user, db):
        resp = auth_admin.post(
            f"/users/{admin_user.id}/edit",
            data={"role": "csr_requester"},
            follow_redirects=True,
        )
        assert b"last active admin" in resp.data.lower()

    def test_cannot_deactivate_last_admin_other(self, client, db):
        """When there are two admins and one tries to deactivate the other (the last remaining)."""
        admin1 = User(username="admin1", role="admin")
        admin1.set_password("pass1")
        admin2 = User(username="admin2", role="admin")
        admin2.set_password("pass2")
        db.session.add_all([admin1, admin2])
        db.session.commit()

        # Login as admin1
        client.post("/auth/login", data={"username": "admin1", "password": "pass1"})

        # Deactivate admin2 - should work since admin1 remains
        resp = client.post(f"/users/{admin2.id}/toggle-active", follow_redirects=True)
        assert b"deactivated" in resp.data.lower()

        # Now try to deactivate admin1 (last active admin) - admin1 can't deactivate self
        resp = client.post(f"/users/{admin1.id}/toggle-active", follow_redirects=True)
        assert b"cannot deactivate your own account" in resp.data.lower()
