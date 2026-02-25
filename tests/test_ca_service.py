from cryptography import x509

from app.services import ca_service
from app.models.ca import CertificateAuthority


def test_create_root_ca_rsa(app, db):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Test Root CA",
            subject_attrs={"CN": "Test Root CA", "O": "Test Org", "C": "US"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )

        assert ca.id is not None
        assert ca.name == "Test Root CA"
        assert ca.is_root is True
        assert ca.key_type == "RSA"
        assert ca.key_size == 2048
        assert ca.parent_id is None

        cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "Test Root CA"

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True


def test_create_root_ca_ec(app, db):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="EC Root CA",
            subject_attrs={"CN": "EC Root CA"},
            key_type="EC",
            key_size=256,
            validity_days=3650,
            passphrase="test-passphrase",
        )

        assert ca.key_type == "EC"
        assert ca.key_size == 256


def test_create_intermediate_ca(app, db):
    with app.app_context():
        root = ca_service.create_root_ca(
            name="Root for Intermediate",
            subject_attrs={"CN": "Root CA"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )

        intermediate = ca_service.create_intermediate_ca(
            name="Intermediate CA",
            parent_ca=root,
            subject_attrs={"CN": "Intermediate CA", "O": "Test"},
            key_type="RSA",
            key_size=2048,
            validity_days=1825,
            passphrase="test-passphrase",
        )

        assert intermediate.is_root is False
        assert intermediate.parent_id == root.id

        cert = x509.load_pem_x509_certificate(intermediate.certificate_pem.encode())
        root_cert = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        assert cert.issuer == root_cert.subject


def test_get_ca_chain(app, db):
    with app.app_context():
        root = ca_service.create_root_ca(
            name="Chain Root",
            subject_attrs={"CN": "Chain Root"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )
        intermediate = ca_service.create_intermediate_ca(
            name="Chain Intermediate",
            parent_ca=root,
            subject_attrs={"CN": "Chain Intermediate"},
            key_type="RSA",
            key_size=2048,
            validity_days=1825,
            passphrase="test-passphrase",
        )

        chain = ca_service.get_ca_chain(intermediate)
        assert "Chain Intermediate" in chain or "BEGIN CERTIFICATE" in chain
        assert chain.count("BEGIN CERTIFICATE") == 2
