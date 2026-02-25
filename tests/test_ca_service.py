import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.services import ca_service, cert_service
from app.models.ca import CertificateAuthority
from app.services.crypto_utils import decrypt_private_key


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


def _extract_pem(ca_model, passphrase="test-passphrase"):
    """Helper to extract cert PEM and key PEM from a CA model."""
    cert_pem = ca_model.certificate_pem
    key = decrypt_private_key(ca_model.private_key_enc, passphrase)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def test_import_root_ca(app, db):
    with app.app_context():
        # Generate a root CA, extract its PEM, delete original, then reimport
        original = ca_service.create_root_ca(
            name="Original Root",
            subject_attrs={"CN": "Original Root", "O": "Test Org"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )
        cert_pem, key_pem = _extract_pem(original)
        db.session.delete(original)
        db.session.commit()

        imported = ca_service.import_ca(
            name="Imported Root",
            cert_pem=cert_pem,
            key_pem=key_pem,
            passphrase="test-passphrase",
        )

        assert imported.is_root is True
        assert imported.parent_id is None
        assert imported.key_type == "RSA"
        assert imported.common_name == "Original Root"
        assert imported.name == "Imported Root"


def test_import_ca_key_mismatch(app, db):
    with app.app_context():
        ca1 = ca_service.create_root_ca(
            name="CA1",
            subject_attrs={"CN": "CA1"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )
        ca2 = ca_service.create_root_ca(
            name="CA2",
            subject_attrs={"CN": "CA2"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )
        cert_pem1, _ = _extract_pem(ca1)
        _, key_pem2 = _extract_pem(ca2)

        with pytest.raises(ValueError, match="does not match"):
            ca_service.import_ca(
                name="Mismatched",
                cert_pem=cert_pem1,
                key_pem=key_pem2,
                passphrase="test-passphrase",
            )


def test_import_ca_not_ca_cert(app, db):
    with app.app_context():
        root = ca_service.create_root_ca(
            name="Root for leaf",
            subject_attrs={"CN": "Root CA"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )
        leaf = cert_service.create_certificate(
            ca=root,
            subject_attrs={"CN": "leaf.example.com"},
            san_list=["leaf.example.com"],
            validity_days=365,
            passphrase="test-passphrase",
            key_type="RSA",
            key_size=2048,
        )

        leaf_cert_pem = leaf.certificate_pem
        leaf_key = decrypt_private_key(leaf.private_key_enc, "test-passphrase")
        leaf_key_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        with pytest.raises(ValueError, match="BasicConstraints"):
            ca_service.import_ca(
                name="Not a CA",
                cert_pem=leaf_cert_pem,
                key_pem=leaf_key_pem,
                passphrase="test-passphrase",
            )


def test_import_ca_duplicate_serial(app, db):
    with app.app_context():
        original = ca_service.create_root_ca(
            name="Original",
            subject_attrs={"CN": "Original"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )
        cert_pem, key_pem = _extract_pem(original)

        with pytest.raises(ValueError, match="already exists"):
            ca_service.import_ca(
                name="Duplicate Serial",
                cert_pem=cert_pem,
                key_pem=key_pem,
                passphrase="test-passphrase",
            )


def test_import_intermediate_auto_detect_parent(app, db):
    with app.app_context():
        root = ca_service.create_root_ca(
            name="Root for auto-detect",
            subject_attrs={"CN": "Root CA"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )
        intermediate = ca_service.create_intermediate_ca(
            name="Intermediate for auto-detect",
            parent_ca=root,
            subject_attrs={"CN": "Intermediate CA"},
            key_type="RSA",
            key_size=2048,
            validity_days=1825,
            passphrase="test-passphrase",
        )
        cert_pem, key_pem = _extract_pem(intermediate)
        db.session.delete(intermediate)
        db.session.commit()

        reimported = ca_service.import_ca(
            name="Reimported Intermediate",
            cert_pem=cert_pem,
            key_pem=key_pem,
            passphrase="test-passphrase",
            parent_id=None,
        )

        assert reimported.parent_id == root.id
        assert reimported.is_root is False


def test_detect_parent_ca(app, db):
    with app.app_context():
        root = ca_service.create_root_ca(
            name="Detect Root",
            subject_attrs={"CN": "Detect Root"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase="test-passphrase",
        )

        is_self_signed, parent_id = ca_service.detect_parent_ca(root.certificate_pem)
        assert is_self_signed is True
        assert parent_id is None
