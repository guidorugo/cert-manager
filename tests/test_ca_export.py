"""Tests for CA export (chain bundle, private key, PKCS#12) and true
HTTP-level export -> wipe -> re-import round trips."""
import io
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.services import ca_service, cert_service

PASS = "test-passphrase"


@pytest.fixture
def ca_pair(db):
    """A root and an intermediate created through the normal services."""
    root = ca_service.create_root_ca(
        "Export Root", {"CN": "Export Root"}, "RSA", 2048, 3650, PASS,
    )
    inter = ca_service.create_intermediate_ca(
        "Export Inter", root, {"CN": "Export Inter"}, "RSA", 2048, 1825, PASS,
    )
    return root, inter


class TestCaExport:
    def test_default_format_serves_certificate(self, auth_admin, ca_pair):
        root, _ = ca_pair
        resp = auth_admin.get(f"/ca/{root.id}/download")
        assert resp.status_code == 200
        assert resp.data.decode().count("BEGIN CERTIFICATE") == 1
        assert "Export_Root.pem" in resp.headers["Content-Disposition"]

    def test_chain_bundle_contains_full_chain(self, auth_admin, ca_pair):
        _, inter = ca_pair
        resp = auth_admin.get(f"/ca/{inter.id}/download?format=chain")
        assert resp.status_code == 200
        assert resp.data.decode().count("BEGIN CERTIFICATE") == 2
        assert "Export_Inter-chain.pem" in resp.headers["Content-Disposition"]

    def test_key_export_matches_certificate(self, auth_admin, ca_pair, db):
        root, _ = ca_pair
        resp = auth_admin.get(f"/ca/{root.id}/download?format=key")
        assert resp.status_code == 200
        key = serialization.load_pem_private_key(resp.data, password=None)
        cert = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        assert key.public_key().public_numbers() == cert.public_key().public_numbers()
        entry = AuditLog.query.filter_by(action="download_ca_private_key").first()
        assert entry is not None and entry.target_id == root.id

    def test_key_export_admin_only(self, auth_csr_requester, ca_pair):
        """Session non-admins are redirected; Basic Auth clients get 403 JSON.
        Either way, no key material is served."""
        import base64

        root, _ = ca_pair
        resp = auth_csr_requester.get(f"/ca/{root.id}/download?format=key")
        assert resp.status_code == 302  # flash + redirect, app convention
        assert b"PRIVATE KEY" not in resp.data

        creds = base64.b64encode(b"testrequester:requesterpass").decode()
        resp = auth_csr_requester.get(
            f"/ca/{root.id}/download?format=key",
            headers={"Authorization": f"Basic {creds}"},
        )
        assert resp.status_code == 403
        assert b"PRIVATE KEY" not in resp.data

    def test_key_export_refused_for_keyless_ca(self, auth_admin, db):
        _, inter = None, None  # noqa: F841 - clarity only
        root = ca_service.create_root_ca(
            "Keyless Export Src", {"CN": "Keyless Export Src"}, "RSA", 2048, 3650, PASS,
        )
        cert_pem = root.certificate_pem
        db.session.delete(root)
        db.session.commit()
        keyless = ca_service.import_ca("Keyless Export", cert_pem, None, PASS)

        resp = auth_admin.get(
            f"/ca/{keyless.id}/download?format=key", follow_redirects=True,
        )
        assert b"there is no key to export" in resp.data
        resp = auth_admin.post(
            f"/ca/{keyless.id}/download",
            data={"format": "pkcs12", "password": "x"},
            follow_redirects=True,
        )
        assert b"PKCS#12 export is not possible" in resp.data

    def test_pkcs12_export_roundtrip_parse(self, auth_admin, ca_pair, db):
        _, inter = ca_pair
        resp = auth_admin.post(
            f"/ca/{inter.id}/download",
            data={"format": "pkcs12", "password": "bundle-pw"},
        )
        assert resp.status_code == 200
        assert resp.mimetype == "application/x-pkcs12"

        key, cert, additional = pkcs12.load_key_and_certificates(resp.data, b"bundle-pw")
        assert key is not None
        assert cert.subject.rfc4514_string() == "CN=Export Inter"
        assert len(additional) == 1  # the root rides along
        assert additional[0].subject.rfc4514_string() == "CN=Export Root"

        with pytest.raises(ValueError):
            pkcs12.load_key_and_certificates(resp.data, b"wrong-pw")

        entry = AuditLog.query.filter_by(action="export_ca_pkcs12").first()
        assert entry is not None and entry.target_id == inter.id

    def test_pkcs12_requires_password(self, auth_admin, ca_pair):
        root, _ = ca_pair
        resp = auth_admin.post(
            f"/ca/{root.id}/download", data={"format": "pkcs12", "password": ""},
            follow_redirects=True,
        )
        assert b"export password is required" in resp.data


class TestExportImportRoundTrip:
    def test_pem_chain_and_key_round_trip(self, auth_admin, ca_pair, db):
        """Export chain+key over HTTP, wipe the CAs, re-import via the
        upload form, then issue a certificate from the restored CA."""
        root, inter = ca_pair
        chain_pem = auth_admin.get(f"/ca/{inter.id}/download?format=chain").data.decode()
        key_pem = auth_admin.get(f"/ca/{inter.id}/download?format=key").data.decode()

        db.session.delete(inter)
        db.session.delete(root)
        db.session.commit()

        resp = auth_admin.post("/ca/create", data={
            "mode": "upload",
            "name": "Restored Inter",
            "cert_pem": chain_pem,
            "key_pem": key_pem,
        }, follow_redirects=False)
        assert resp.status_code == 302

        restored = CertificateAuthority.query.filter_by(name="Restored Inter").one()
        assert restored.has_private_key
        parent = db.session.get(CertificateAuthority, restored.parent_id)
        assert parent.common_name == "Export Root"
        assert parent.has_private_key is False  # chain parents come back cert-only

        leaf = cert_service.create_certificate(
            ca=restored, subject_attrs={"CN": "rt.example.test"},
            san_list=["rt.example.test"], validity_days=365, passphrase=PASS,
        )
        assert leaf.id is not None

    def test_pkcs12_round_trip(self, auth_admin, ca_pair, db):
        """Export a .p12 over HTTP, wipe the CAs, re-import the bundle via
        the PKCS#12 upload form, then issue a certificate."""
        root, inter = ca_pair
        p12_bytes = auth_admin.post(
            f"/ca/{inter.id}/download",
            data={"format": "pkcs12", "password": "rt-pw"},
        ).data

        db.session.delete(inter)
        db.session.delete(root)
        db.session.commit()

        resp = auth_admin.post("/ca/create", data={
            "mode": "upload",
            "name": "Restored P12 Inter",
            "import_format": "pkcs12",
            "p12_password": "rt-pw",
            "p12_file": (io.BytesIO(p12_bytes), "export.p12"),
        }, content_type="multipart/form-data", follow_redirects=False)
        assert resp.status_code == 302

        restored = CertificateAuthority.query.filter_by(name="Restored P12 Inter").one()
        assert restored.has_private_key
        parent = db.session.get(CertificateAuthority, restored.parent_id)
        assert parent.common_name == "Export Root"

        leaf = cert_service.create_certificate(
            ca=restored, subject_attrs={"CN": "p12rt.example.test"},
            san_list=["p12rt.example.test"], validity_days=365, passphrase=PASS,
        )
        assert leaf.id is not None

        details = json.loads(
            AuditLog.query.filter_by(action="import_ca").first().details
        )
        assert details["format"] == "pkcs12"
