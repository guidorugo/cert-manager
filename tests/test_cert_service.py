import json

from cryptography import x509

from app.services import ca_service, cert_service, csr_service, crl_service
from app.models.certificate import Certificate


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
