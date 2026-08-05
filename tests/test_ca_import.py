"""Tests for the CA import overhaul: encrypted keys, certificate-only
imports, PKCS#12 bundles, and chain bundles.

Certificates here are built directly with cryptography (no DB round-trips),
so imports are exercised exactly like foreign material would be.
"""
import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ocsp

from app.models.audit_log import AuditLog
from app.models.ca import CertificateAuthority
from app.services import ca_service, cert_service, crl_service, ocsp_service
from app.services.crypto_utils import decrypt_private_key

PASS = "test-passphrase"


def _name(cn):
    return x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])


def _self_signed_ca(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _child_ca(cn, parent_key, parent_cert, signing_key=None):
    """Build an intermediate under parent. signing_key overrides the signer
    to craft chains that do NOT verify."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(parent_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(signing_key or parent_key, hashes.SHA256())
    )
    return key, cert


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key, password=None):
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    ).decode()


class TestEncryptedKeyImport:
    def test_encrypted_key_roundtrip(self, db):
        key, cert = _self_signed_ca("Encrypted Root")
        ca = ca_service.import_ca(
            "Encrypted Root", _pem(cert), _key_pem(key, b"key-pass"), PASS,
            key_passphrase="key-pass",
        )
        assert ca.has_private_key
        # stored key decrypts with the master passphrase and matches the cert
        stored = decrypt_private_key(ca.private_key_enc, PASS)
        assert stored.public_key().public_numbers() == key.public_key().public_numbers()

    def test_wrong_key_passphrase(self, db):
        key, cert = _self_signed_ca("Enc Root 2")
        with pytest.raises(ValueError, match="Could not decrypt"):
            ca_service.import_ca(
                "Enc Root 2", _pem(cert), _key_pem(key, b"right"), PASS,
                key_passphrase="wrong",
            )

    def test_missing_passphrase_for_encrypted_key(self, db):
        key, cert = _self_signed_ca("Enc Root 3")
        with pytest.raises(ValueError, match="is encrypted"):
            ca_service.import_ca("Enc Root 3", _pem(cert), _key_pem(key, b"kp"), PASS)

    def test_passphrase_for_unencrypted_key(self, db):
        key, cert = _self_signed_ca("Enc Root 4")
        with pytest.raises(ValueError, match="not encrypted"):
            ca_service.import_ca(
                "Enc Root 4", _pem(cert), _key_pem(key), PASS, key_passphrase="oops",
            )


class TestCertOnlyImport:
    def test_import_without_key(self, db):
        _, cert = _self_signed_ca("Offline Root")
        ca = ca_service.import_ca("Offline Root", _pem(cert), None, PASS)
        assert ca.has_private_key is False
        assert ca.is_root is True
        assert ca.key_type == "RSA"
        assert ca.key_size == 2048

    def test_keyless_cannot_issue(self, db):
        _, cert = _self_signed_ca("Offline Root I")
        ca = ca_service.import_ca("Offline Root I", _pem(cert), None, PASS)
        with pytest.raises(ValueError, match="cannot issue"):
            cert_service.create_certificate(
                ca=ca, subject_attrs={"CN": "x"}, san_list=[],
                validity_days=365, passphrase=PASS,
            )

    def test_keyless_cannot_generate_crl(self, db):
        _, cert = _self_signed_ca("Offline Root C")
        ca = ca_service.import_ca("Offline Root C", _pem(cert), None, PASS)
        with pytest.raises(ValueError, match="cannot sign CRLs"):
            crl_service.generate_crl(ca, PASS)

    def test_keyless_cannot_parent_generated_intermediate(self, db):
        _, cert = _self_signed_ca("Offline Root P")
        ca = ca_service.import_ca("Offline Root P", _pem(cert), None, PASS)
        with pytest.raises(ValueError, match="cannot sign a new intermediate"):
            ca_service.create_intermediate_ca(
                "Child", ca, {"CN": "Child"}, "RSA", 2048, 365, PASS,
            )

    def test_keyless_ocsp_returns_unauthorized(self, db):
        _, cert = _self_signed_ca("Offline Root O")
        ca = ca_service.import_ca("Offline Root O", _pem(cert), None, PASS)
        der = ocsp_service.build_ocsp_response(b"irrelevant", ca, PASS)
        resp = ocsp.load_der_ocsp_response(der)
        assert resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED

    def test_keyless_excluded_from_issuing_dropdown(self, auth_admin, db):
        _, cert = _self_signed_ca("OfflineRootZZZ")
        ca_service.import_ca("OfflineRootZZZ", _pem(cert), None, PASS)
        signing = ca_service.create_root_ca(
            "SigningRootZZZ", {"CN": "SigningRootZZZ"}, "RSA", 2048, 3650, PASS,
        )
        resp = auth_admin.get("/certificates/create")
        html = resp.data.decode()
        assert "SigningRootZZZ" in html
        assert "OfflineRootZZZ" not in html
        assert signing.id is not None

    def test_intermediate_with_key_under_keyless_root(self, db):
        root_key, root_cert = _self_signed_ca("Offline Chain Root")
        int_key, int_cert = _child_ca("Online Intermediate", root_key, root_cert)

        root_ca = ca_service.import_ca("Offline Chain Root", _pem(root_cert), None, PASS)
        int_ca = ca_service.import_ca(
            "Online Intermediate", _pem(int_cert), _key_pem(int_key), PASS,
        )
        assert int_ca.parent_id == root_ca.id  # auto-detected
        assert int_ca.has_private_key

        # The intermediate can issue even though its root is keyless
        leaf = cert_service.create_certificate(
            ca=int_ca, subject_attrs={"CN": "leaf.example.test"},
            san_list=["leaf.example.test"], validity_days=365, passphrase=PASS,
        )
        assert leaf.id is not None
        chain = ca_service.get_ca_chain(int_ca)
        assert chain.count("BEGIN CERTIFICATE") == 2


class TestChainImport:
    def test_chain_bundle_imports_parents_cert_only(self, db):
        root_key, root_cert = _self_signed_ca("Bundle Root")
        int_key, int_cert = _child_ca("Bundle Intermediate", root_key, root_cert)

        # Root first on purpose: order must not matter
        bundle = _pem(root_cert) + _pem(int_cert)
        ca = ca_service.import_ca("My Intermediate", bundle, _key_pem(int_key), PASS)

        assert ca.has_private_key
        assert ca._imported_parents == ["Bundle Root"]
        parent = db.session.get(CertificateAuthority, ca.parent_id)
        assert parent.common_name == "Bundle Root"
        assert parent.has_private_key is False
        assert parent.is_root is True

    def test_chain_dedup_reuses_existing_parent(self, db):
        root_key, root_cert = _self_signed_ca("Shared Root")
        int1_key, int1_cert = _child_ca("Inter One", root_key, root_cert)
        int2_key, int2_cert = _child_ca("Inter Two", root_key, root_cert)

        ca1 = ca_service.import_ca(
            "Inter One", _pem(int1_cert) + _pem(root_cert), _key_pem(int1_key), PASS,
        )
        ca2 = ca_service.import_ca(
            "Inter Two", _pem(int2_cert) + _pem(root_cert), _key_pem(int2_key), PASS,
        )
        assert ca2._imported_parents == []  # root already known
        assert ca1.parent_id == ca2.parent_id
        root_serial = format(root_cert.serial_number, "x")
        assert CertificateAuthority.query.filter_by(serial_number=root_serial).count() == 1

    def test_unrelated_certs_rejected(self, db):
        _, root_a = _self_signed_ca("Unrelated A")
        _, root_b = _self_signed_ca("Unrelated B")
        with pytest.raises(ValueError, match="does not form a single chain"):
            ca_service.import_ca("Nope", _pem(root_a) + _pem(root_b), None, PASS)

    def test_forged_chain_signature_rejected(self, db):
        root_key, root_cert = _self_signed_ca("Real Root")
        other_key, _ = _self_signed_ca("Evil Root")
        # Claims to be issued by Real Root but is signed by Evil Root's key
        _, forged = _child_ca("Forged Inter", root_key, root_cert, signing_key=other_key)
        with pytest.raises(ValueError, match="does not verify"):
            ca_service.import_ca("Forged", _pem(forged) + _pem(root_cert), None, PASS)

    def test_wrong_key_for_chain_leaf(self, db):
        root_key, root_cert = _self_signed_ca("KeyChk Root")
        int_key, int_cert = _child_ca("KeyChk Inter", root_key, root_cert)
        with pytest.raises(ValueError, match="does not match"):
            ca_service.import_ca(
                "KeyChk", _pem(int_cert) + _pem(root_cert), _key_pem(root_key), PASS,
            )

    def test_detect_parent_accepts_bundle(self, db):
        root_key, root_cert = _self_signed_ca("Detect Root")
        _, int_cert = _child_ca("Detect Inter", root_key, root_cert)
        root_ca = ca_service.import_ca("Detect Root", _pem(root_cert), None, PASS)

        is_self_signed, parent_id = ca_service.detect_parent_ca(
            _pem(int_cert) + _pem(root_cert)
        )
        assert is_self_signed is False
        assert parent_id == root_ca.id


class TestPkcs12Import:
    def test_p12_with_password(self, db):
        key, cert = _self_signed_ca("P12 Root")
        p12 = pkcs12.serialize_key_and_certificates(
            b"p12root", key, cert, None,
            serialization.BestAvailableEncryption(b"p12-pass"),
        )
        ca = ca_service.import_pkcs12("P12 Root", p12, "p12-pass", PASS)
        assert ca.has_private_key
        assert ca.common_name == "P12 Root"

    def test_p12_wrong_password(self, db):
        key, cert = _self_signed_ca("P12 Root W")
        p12 = pkcs12.serialize_key_and_certificates(
            b"x", key, cert, None, serialization.BestAvailableEncryption(b"right"),
        )
        with pytest.raises(ValueError, match="Could not open"):
            ca_service.import_pkcs12("P12 Root W", p12, "wrong", PASS)

    def test_p12_without_key_is_cert_only(self, db):
        _, cert = _self_signed_ca("P12 CertOnly")
        p12 = pkcs12.serialize_key_and_certificates(
            b"x", None, cert, None, serialization.NoEncryption(),
        )
        ca = ca_service.import_pkcs12("P12 CertOnly", p12, None, PASS)
        assert ca.has_private_key is False

    def test_p12_with_bundled_chain(self, db):
        root_key, root_cert = _self_signed_ca("P12 Chain Root")
        int_key, int_cert = _child_ca("P12 Chain Inter", root_key, root_cert)
        p12 = pkcs12.serialize_key_and_certificates(
            b"x", int_key, int_cert, [root_cert], serialization.NoEncryption(),
        )
        ca = ca_service.import_pkcs12("P12 Chain Inter", p12, None, PASS)
        assert ca.has_private_key
        assert ca._imported_parents == ["P12 Chain Root"]
        parent = db.session.get(CertificateAuthority, ca.parent_id)
        assert parent.has_private_key is False


class TestImportRoutes:
    def test_upload_cert_only_via_form(self, auth_admin, db):
        _, cert = _self_signed_ca("Form Offline Root")
        resp = auth_admin.post("/ca/create", data={
            "mode": "upload",
            "name": "Form Offline Root",
            "cert_pem": _pem(cert),
            "cert_only": "on",
        }, follow_redirects=False)
        assert resp.status_code == 302

        ca = CertificateAuthority.query.filter_by(name="Form Offline Root").one()
        assert ca.has_private_key is False
        entry = AuditLog.query.filter_by(action="import_ca").first()
        details = json.loads(entry.details)
        assert details["has_key"] is False
        assert details["format"] == "pem"

    def test_upload_key_and_cert_only_conflict(self, auth_admin, db):
        key, cert = _self_signed_ca("Conflict Root")
        resp = auth_admin.post("/ca/create", data={
            "mode": "upload",
            "name": "Conflict Root",
            "cert_pem": _pem(cert),
            "key_pem": _key_pem(key),
            "cert_only": "on",
        })
        assert b"remove one of the two" in resp.data
        assert CertificateAuthority.query.filter_by(name="Conflict Root").count() == 0

    def test_upload_pkcs12_via_form(self, auth_admin, db):
        key, cert = _self_signed_ca("Form P12 Root")
        p12 = pkcs12.serialize_key_and_certificates(
            b"x", key, cert, None, serialization.BestAvailableEncryption(b"pw"),
        )
        resp = auth_admin.post("/ca/create", data={
            "mode": "upload",
            "name": "Form P12 Root",
            "import_format": "pkcs12",
            "p12_password": "pw",
            "p12_file": (io.BytesIO(p12), "bundle.p12"),
        }, content_type="multipart/form-data", follow_redirects=False)
        assert resp.status_code == 302

        ca = CertificateAuthority.query.filter_by(name="Form P12 Root").one()
        assert ca.has_private_key is True

    def test_public_crl_404_for_keyless_ca(self, client, db):
        _, cert = _self_signed_ca("Keyless Public Root")
        ca = ca_service.import_ca("Keyless Public Root", _pem(cert), None, PASS)
        assert client.get(f"/public/crl/{ca.id}.crl").status_code == 404
        assert client.get(f"/public/crl/{ca.id}.pem").status_code == 404

    def test_generate_crl_route_flashes_specific_error(self, auth_admin, db):
        _, cert = _self_signed_ca("Keyless Flash Root")
        ca = ca_service.import_ca("Keyless Flash Root", _pem(cert), None, PASS)
        resp = auth_admin.post(f"/ca/{ca.id}/crl", follow_redirects=True)
        assert b"cannot sign CRLs" in resp.data

    def test_ocsp_response_mirrors_request_hash(self, db):
        """openssl requests with SHA-1 by default; the CertID hash in the
        response must match the request's or clients report no status."""
        root = ca_service.create_root_ca(
            "OCSP Hash Root", {"CN": "OCSP Hash Root"}, "RSA", 2048, 3650, PASS,
        )
        leaf = cert_service.create_certificate(
            ca=root, subject_attrs={"CN": "h.test"}, san_list=[],
            validity_days=365, passphrase=PASS,
        )
        root_cert = x509.load_pem_x509_certificate(root.certificate_pem.encode())
        leaf_cert = x509.load_pem_x509_certificate(leaf.certificate_pem.encode())

        for algo_cls in (hashes.SHA1, hashes.SHA256):
            req = (
                ocsp.OCSPRequestBuilder()
                .add_certificate(leaf_cert, root_cert, algo_cls())
                .build()
            )
            der = ocsp_service.build_ocsp_response(
                req.public_bytes(serialization.Encoding.DER), root, PASS,
            )
            resp = ocsp.load_der_ocsp_response(der)
            assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
            assert isinstance(resp.hash_algorithm, algo_cls)
            assert resp.certificate_status == ocsp.OCSPCertStatus.GOOD

    def test_upload_chain_via_form_flashes_parents(self, auth_admin, db):
        root_key, root_cert = _self_signed_ca("Form Chain Root")
        int_key, int_cert = _child_ca("Form Chain Inter", root_key, root_cert)
        resp = auth_admin.post("/ca/create", data={
            "mode": "upload",
            "name": "Form Chain Inter",
            "cert_pem": _pem(int_cert) + _pem(root_cert),
            "key_pem": _key_pem(int_key),
        }, follow_redirects=True)
        assert b"1 parent CA(s) imported" in resp.data
        assert CertificateAuthority.query.filter_by(common_name="Form Chain Root").count() == 1
