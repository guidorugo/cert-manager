"""Key-backend abstraction tests (finding A1, Phase 1).

Phase 1 introduces a `KeyBackend` seam with the software backend as the only
implementation. These tests lock in two things:

1. New CAs default to the software backend and the three-state guards
   (`has_signing_key` / `is_exportable`) behave as before for software CAs.
2. The software backend's signing output is *stable* — signing the same builder
   twice yields byte-identical DER (RSA PKCS#1 v1.5 is deterministic). This is
   the reference the Phase 2 differential test compares the HSM backend against,
   and it proves the new "build a pyca builder, hand it to the backend to sign"
   seam reproduces exactly what `builder.sign(...)` produced before.
"""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from app.services import ca_service, cert_service, ocsp_service
from app.services.crypto_utils import decrypt_private_key
from app.services.keybackend import (
    backend_for_ca,
    get_backend,
    OcspResponseSpec,
)
from app.services.keybackend.software import SoftwareBackend
from app.models.ca import CertificateAuthority


PASSPHRASE = "test-passphrase"


@pytest.fixture
def root_ca(app, db):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Backend Root CA",
            subject_attrs={"CN": "Backend Root CA", "O": "Test Org", "C": "US"},
            key_type="RSA",
            key_size=2048,
            validity_days=3650,
            passphrase=PASSPHRASE,
        )
        yield ca


def _leaf_builder(ca):
    """A minimal, fully-determined leaf CertificateBuilder issued by `ca`."""
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(0x0BADC0DE)  # pinned so DER is fully deterministic
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    ), ca_cert


# --- registry / model guards -------------------------------------------------

def test_new_ca_defaults_to_software_backend(root_ca):
    assert root_ca.key_backend == "software"
    assert root_ca.has_signing_key is True
    assert root_ca.is_exportable is True
    assert isinstance(get_backend(None), SoftwareBackend)
    assert isinstance(backend_for_ca(root_ca), SoftwareBackend)


def test_get_backend_unknown_raises():
    with pytest.raises(ValueError):
        get_backend("does-not-exist")


def test_backend_for_ca_rejects_keyless(app, db):
    """A certificate-only import (empty-bytes sentinel) has no signing key."""
    with app.app_context():
        ca = CertificateAuthority(
            name="Keyless", common_name="Keyless", serial_number="01",
            certificate_pem="x", private_key_enc=b"", key_type="RSA", key_size=2048,
            not_before=datetime.now(timezone.utc), not_after=datetime.now(timezone.utc),
            key_backend="software",
        )
        assert ca.has_signing_key is False
        assert ca.is_exportable is False
        with pytest.raises(ValueError):
            backend_for_ca(ca)


# --- signing stability (the Phase 2 parity reference) ------------------------

def test_sign_certificate_is_byte_stable(root_ca, app):
    """RSA PKCS#1 v1.5 is deterministic: same builder → identical DER."""
    with app.app_context():
        backend = backend_for_ca(root_ca)
        builder, ca_cert = _leaf_builder(root_ca)
        der1 = backend.sign_certificate(builder, root_ca, secret=PASSPHRASE)
        der2 = backend.sign_certificate(builder, root_ca, secret=PASSPHRASE)
        assert der1 == der2
        # And it is a real, correctly-issued certificate.
        leaf = x509.load_der_x509_certificate(der1)
        leaf.verify_directly_issued_by(ca_cert)


def test_sign_certificate_matches_direct_pyca(root_ca, app):
    """The backend seam reproduces exactly what `builder.sign(key)` produced."""
    with app.app_context():
        builder, _ = _leaf_builder(root_ca)
        ca_key = decrypt_private_key(root_ca.private_key_enc, PASSPHRASE)
        direct = builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        via_backend = backend_for_ca(root_ca).sign_certificate(builder, root_ca, secret=PASSPHRASE)
        assert via_backend == direct


def test_sign_ocsp_roundtrips_and_verifies(root_ca, app):
    with app.app_context():
        ca_cert = x509.load_pem_x509_certificate(root_ca.certificate_pem.encode())
        # Reuse a real leaf so subject/issuer line up.
        builder, _ = _leaf_builder(root_ca)
        leaf_der = backend_for_ca(root_ca).sign_certificate(builder, root_ca, secret=PASSPHRASE)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        spec = OcspResponseSpec(
            subject_cert_der=leaf_der,
            issuer_cert_der=ca_cert.public_bytes(serialization.Encoding.DER),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=now + timedelta(days=1),
            revocation_time=None,
            revocation_reason=None,
            algorithm=hashes.SHA1(),  # mirror a typical openssl request
        )
        der = backend_for_ca(root_ca).sign_ocsp(spec, root_ca, secret=PASSPHRASE)
        resp = ocsp.load_der_ocsp_response(der)
        assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
        assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD
        # responder is byKey (HASH), no embedded certs — matches prior behaviour
        assert resp.responder_key_hash is not None


def test_can_export(root_ca, app):
    with app.app_context():
        assert backend_for_ca(root_ca).can_export() is True
