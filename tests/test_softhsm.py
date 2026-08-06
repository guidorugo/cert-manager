"""SoftHSM backend tests (finding A1, Phase 2).

The correctness anchor: sign the *same* pinned certificate two ways —
SoftwareBackend with an RSA key, and Pkcs11Backend with the same key imported
into a SoftHSM token — and assert the DER is byte-identical. RSA PKCS#1 v1.5 is
deterministic, so any divergence in the TBS bytes, algorithm identifiers, or
signature encoding fails the test. EC is randomized, so there we assert the TBS
is identical and the certificate verifies.

Skips entirely where python-pkcs11 / SoftHSM are not installed; CI installs
softhsm2 so this runs in the pipeline and gates the published image.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("pkcs11")  # skip whole module if the library is absent

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID

from app.services import ca_service
from app.services.crypto_utils import decrypt_private_key
from app.services.keybackend import get_backend, pkcs11_session
from app.services.keybackend.softhsm import Pkcs11Backend
from app.services.keybackend.base import OcspResponseSpec


PASSPHRASE = "test-passphrase"


@pytest.fixture
def hsm_config(app, softhsm_token):
    """Point app config at the session SoftHSM token; reset session caches."""
    keys = ("KEY_BACKEND", "PKCS11_MODULE", "PKCS11_TOKEN_LABEL", "PKCS11_USER_PIN")
    prev = {k: app.config.get(k) for k in keys}
    app.config["PKCS11_MODULE"] = softhsm_token["module"]
    app.config["PKCS11_TOKEN_LABEL"] = softhsm_token["label"]
    app.config["PKCS11_USER_PIN"] = softhsm_token["user_pin"]
    pkcs11_session.reset()
    yield softhsm_token
    for k, v in prev.items():
        app.config[k] = v
    pkcs11_session.reset()


def _leaf_builder(ca):
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(0x0BADC0DE)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )


def _hsm_ca(ca, label):
    """A stand-in CA object that reads as HSM-backed for the backend."""
    return SimpleNamespace(
        certificate_pem=ca.certificate_pem,
        key_label=label,
        key_backend="softhsm",
        private_key_enc=b"",
        has_signing_key=True,
    )


# --- the differential parity gate -------------------------------------------

def test_rsa_leaf_der_is_byte_identical(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Diff Root RSA", subject_attrs={"CN": "Diff Root RSA"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE,
        )
        ca_key = decrypt_private_key(ca.private_key_enc, PASSPHRASE)
        Pkcs11Backend().import_ca_key(ca_key, label="diff-rsa")

        builder = _leaf_builder(ca)
        soft_der = get_backend("software").sign_certificate(builder, ca, secret=PASSPHRASE)
        hsm_der = Pkcs11Backend().sign_certificate(builder, _hsm_ca(ca, "diff-rsa"))

        assert hsm_der == soft_der  # RSA is deterministic -> exact byte parity
        leaf = x509.load_der_x509_certificate(hsm_der)
        leaf.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.certificate_pem.encode()))


def test_ec_leaf_tbs_identical_and_verifies(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Diff Root EC", subject_attrs={"CN": "Diff Root EC"},
            key_type="EC", key_size=256, validity_days=3650, passphrase=PASSPHRASE,
        )
        ca_key = decrypt_private_key(ca.private_key_enc, PASSPHRASE)
        Pkcs11Backend().import_ca_key(ca_key, label="diff-ec")

        builder = _leaf_builder(ca)
        soft_der = get_backend("software").sign_certificate(builder, ca, secret=PASSPHRASE)
        hsm_der = Pkcs11Backend().sign_certificate(builder, _hsm_ca(ca, "diff-ec"))

        # ECDSA is randomized: the signature differs, but the TBS must match...
        soft = x509.load_der_x509_certificate(soft_der)
        hsm = x509.load_der_x509_certificate(hsm_der)
        assert hsm.tbs_certificate_bytes == soft.tbs_certificate_bytes
        # ...and the token's signature must verify against the CA public key.
        hsm.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.certificate_pem.encode()))


# --- key generation ---------------------------------------------------------

def test_generate_rsa_key_in_token(app, db, hsm_config):
    with app.app_context():
        pub, label = Pkcs11Backend().generate_ca_key("RSA", 2048, label="gen-rsa")
        assert isinstance(pub, rsa.RSAPublicKey)
        assert pub.key_size == 2048
        # The token holds a matching, usable private key (never left the token).
        from pkcs11 import ObjectClass, Mechanism
        data = b"to-be-signed"
        with pkcs11_session.session_scope() as s:
            priv = s.get_key(object_class=ObjectClass.PRIVATE_KEY, label=label)
            sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())


def test_generate_ec_key_in_token(app, db, hsm_config):
    with app.app_context():
        pub, label = Pkcs11Backend().generate_ca_key("EC", 256, label="gen-ec")
        assert isinstance(pub, ec.EllipticCurvePublicKey)
        assert pub.curve.name == "secp256r1"
        import hashlib
        from pkcs11 import ObjectClass, Mechanism
        from pkcs11.util.ec import encode_ecdsa_signature
        data = b"to-be-signed"
        with pkcs11_session.session_scope() as s:
            priv = s.get_key(object_class=ObjectClass.PRIVATE_KEY, label=label)
            raw = priv.sign(hashlib.sha256(data).digest(), mechanism=Mechanism.ECDSA)
        pub.verify(encode_ecdsa_signature(raw), data, ec.ECDSA(hashes.SHA256()))


# --- Phase-2 boundaries -----------------------------------------------------

def test_crl_and_ocsp_not_yet_supported(app, db, hsm_config):
    with app.app_context():
        ca = ca_service.create_root_ca(
            name="Boundary Root", subject_attrs={"CN": "Boundary Root"},
            key_type="RSA", key_size=2048, validity_days=3650, passphrase=PASSPHRASE,
        )
        backend = Pkcs11Backend()
        with pytest.raises(NotImplementedError):
            backend.sign_crl(None, _hsm_ca(ca, "x"))
        spec = OcspResponseSpec(
            subject_cert_der=b"", issuer_cert_der=b"",
            cert_status=None, this_update=None, next_update=None,
            revocation_time=None, revocation_reason=None, algorithm=None,
        )
        with pytest.raises(NotImplementedError):
            backend.sign_ocsp(spec, _hsm_ca(ca, "x"))
        assert backend.can_export() is False
