import base64
import json

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from app.services import ca_service, cert_service, csr_service, crl_service
from app.models.certificate import Certificate


def _basic_auth_headers(username, password):
    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


def _create_test_ca(passphrase="test-passphrase"):
    return ca_service.create_root_ca(
        name="Cert Test CA",
        subject_attrs={"CN": "Cert Test CA", "O": "Test"},
        key_type="RSA",
        key_size=2048,
        validity_days=3650,
        passphrase=passphrase,
    )


def test_create_certificate(app, db):
    with app.app_context():
        ca = _create_test_ca()
        cert = cert_service.create_certificate(
            ca=ca,
            subject_attrs={"CN": "test.example.com", "O": "Test"},
            san_list=["test.example.com", "IP:127.0.0.1"],
            validity_days=365,
            passphrase="test-passphrase",
        )

        assert cert.id is not None
        assert cert.common_name == "test.example.com"
        assert cert.private_key_enc is not None

        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        san = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "test.example.com" in dns_names


def test_sign_csr(app, db):
    with app.app_context():
        ca = _create_test_ca()
        csr_model, key_pem, _ = csr_service.create_csr(
            subject_attrs={"CN": "csr.example.com"},
            san_list=["csr.example.com"],
            key_type="RSA",
            key_size=2048,
        )

        cert = cert_service.sign_csr(
            csr_model=csr_model,
            ca=ca,
            validity_days=365,
            passphrase="test-passphrase",
        )

        assert cert.common_name == "csr.example.com"
        assert csr_model.status == "approved"
        assert csr_model.certificate_id == cert.id


def test_export_formats(app, db):
    with app.app_context():
        ca = _create_test_ca()
        cert = cert_service.create_certificate(
            ca=ca,
            subject_attrs={"CN": "export.example.com"},
            san_list=[],
            validity_days=365,
            passphrase="test-passphrase",
        )

        pem = cert_service.export_certificate_pem(cert)
        assert "BEGIN CERTIFICATE" in pem

        der = cert_service.export_certificate_der(cert)
        assert isinstance(der, bytes)
        assert len(der) > 0

        p12 = cert_service.export_pkcs12(cert, "test-passphrase", "export-pw")
        assert isinstance(p12, bytes)
        assert len(p12) > 0


def test_revoke_and_crl(app, db):
    with app.app_context():
        ca = _create_test_ca()
        cert = cert_service.create_certificate(
            ca=ca,
            subject_attrs={"CN": "revoke.example.com"},
            san_list=[],
            validity_days=365,
            passphrase="test-passphrase",
        )

        crl_service.revoke_certificate(cert.id, "key_compromise")
        assert cert.is_revoked is True
        assert cert.revocation_reason == "key_compromise"

        crl = crl_service.generate_crl(ca, "test-passphrase")
        revoked = list(crl)
        assert len(revoked) == 1
        assert revoked[0].serial_number == int(cert.serial_number, 16)


def test_create_certificate_custom_key_usage(app, db):
    with app.app_context():
        ca = _create_test_ca()
        key_usage = {
            "digital_signature": True,
            "key_encipherment": False,
            "content_commitment": False,
            "data_encipherment": False,
            "key_agreement": False,
        }
        cert = cert_service.create_certificate(
            ca=ca,
            subject_attrs={"CN": "ku.example.com"},
            san_list=[],
            validity_days=365,
            passphrase="test-passphrase",
            key_usage=key_usage,
        )

        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        ku_ext = x509_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku_ext.value.digital_signature is True
        assert ku_ext.value.key_encipherment is False
        assert ku_ext.critical is True


def test_create_certificate_custom_eku(app, db):
    with app.app_context():
        ca = _create_test_ca()
        cert = cert_service.create_certificate(
            ca=ca,
            subject_attrs={"CN": "eku.example.com"},
            san_list=[],
            validity_days=365,
            passphrase="test-passphrase",
            extended_key_usage=["codeSigning"],
        )

        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        eku_ext = x509_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = list(eku_ext.value)
        assert ExtendedKeyUsageOID.CODE_SIGNING in oids
        assert ExtendedKeyUsageOID.SERVER_AUTH not in oids


def test_create_certificate_crl_dp(app, db):
    with app.app_context():
        ca = _create_test_ca()
        crl_url = "http://localhost:5000/public/crl/1.crl"
        cert = cert_service.create_certificate(
            ca=ca,
            subject_attrs={"CN": "crldp.example.com"},
            san_list=[],
            validity_days=365,
            passphrase="test-passphrase",
            crl_dp_url=crl_url,
        )

        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        dp_ext = x509_cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        dps = list(dp_ext.value)
        assert len(dps) == 1
        assert dps[0].full_name[0].value == crl_url


def test_sign_csr_custom_ku_eku(app, db):
    with app.app_context():
        ca = _create_test_ca()
        csr_model, _, _ = csr_service.create_csr(
            subject_attrs={"CN": "csrku.example.com"},
            san_list=["csrku.example.com"],
            key_type="RSA",
            key_size=2048,
        )

        key_usage = {
            "digital_signature": True,
            "key_encipherment": False,
            "content_commitment": True,
            "data_encipherment": False,
            "key_agreement": False,
        }
        cert = cert_service.sign_csr(
            csr_model=csr_model,
            ca=ca,
            validity_days=365,
            passphrase="test-passphrase",
            key_usage=key_usage,
            extended_key_usage=["emailProtection"],
        )

        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        ku_ext = x509_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku_ext.value.digital_signature is True
        assert ku_ext.value.key_encipherment is False
        assert ku_ext.value.content_commitment is True

        eku_ext = x509_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = list(eku_ext.value)
        assert ExtendedKeyUsageOID.EMAIL_PROTECTION in oids
        assert len(oids) == 1


def test_sign_csr_crl_dp(app, db):
    with app.app_context():
        ca = _create_test_ca()
        csr_model, _, _ = csr_service.create_csr(
            subject_attrs={"CN": "csrcrldp.example.com"},
            san_list=[],
            key_type="RSA",
            key_size=2048,
        )

        crl_url = "http://ca.example.com/public/crl/1.crl"
        cert = cert_service.sign_csr(
            csr_model=csr_model,
            ca=ca,
            validity_days=365,
            passphrase="test-passphrase",
            crl_dp_url=crl_url,
        )

        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        dp_ext = x509_cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        dps = list(dp_ext.value)
        assert len(dps) == 1
        assert dps[0].full_name[0].value == crl_url


def test_api_create_cert_without_ku_eku_uses_defaults(app, client, admin_user, db):
    """API calls without ku_*/eku_* fields should use service defaults."""
    with app.app_context():
        ca = _create_test_ca()
        resp = client.post("/certificates/create", data={
            "ca_id": str(ca.id),
            "cn": "api-default.example.com",
            "validity_days": "365",
            "key_type": "RSA",
            "key_size": "2048",
        }, headers=_basic_auth_headers("testadmin", "adminpass"),
           follow_redirects=True)
        assert resp.status_code == 200

        cert = Certificate.query.filter_by(common_name="api-default.example.com").first()
        assert cert is not None
        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        ku_ext = x509_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku_ext.value.digital_signature is True
        assert ku_ext.value.key_encipherment is True
        eku_ext = x509_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = list(eku_ext.value)
        assert ExtendedKeyUsageOID.SERVER_AUTH in oids
        assert ExtendedKeyUsageOID.CLIENT_AUTH in oids


def test_api_create_cert_with_custom_ku_eku(app, client, admin_user, db):
    """API calls with explicit ku_*/eku_* fields should use those values."""
    with app.app_context():
        ca = _create_test_ca()
        resp = client.post("/certificates/create", data={
            "ca_id": str(ca.id),
            "cn": "api-custom.example.com",
            "validity_days": "365",
            "key_type": "RSA",
            "key_size": "2048",
            "ku_digital_signature": "on",
            "eku_codeSigning": "on",
        }, headers=_basic_auth_headers("testadmin", "adminpass"),
           follow_redirects=True)
        assert resp.status_code == 200

        cert = Certificate.query.filter_by(common_name="api-custom.example.com").first()
        assert cert is not None
        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        ku_ext = x509_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku_ext.value.digital_signature is True
        assert ku_ext.value.key_encipherment is False
        eku_ext = x509_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oids = list(eku_ext.value)
        assert ExtendedKeyUsageOID.CODE_SIGNING in oids
        assert ExtendedKeyUsageOID.SERVER_AUTH not in oids


def test_api_sign_csr_without_ku_eku_uses_defaults(app, client, admin_user, db):
    """API CSR signing without ku_*/eku_* fields should use service defaults."""
    with app.app_context():
        ca = _create_test_ca()
        csr_model, _, _ = csr_service.create_csr(
            subject_attrs={"CN": "api-csr.example.com"},
            san_list=[], key_type="RSA", key_size=2048,
        )
        resp = client.post(f"/csr/{csr_model.id}/sign", data={
            "ca_id": str(ca.id),
            "validity_days": "365",
        }, headers=_basic_auth_headers("testadmin", "adminpass"),
           follow_redirects=True)
        assert resp.status_code == 200

        cert = Certificate.query.filter_by(common_name="api-csr.example.com").first()
        assert cert is not None
        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
        ku_ext = x509_cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku_ext.value.digital_signature is True
        assert ku_ext.value.key_encipherment is True
