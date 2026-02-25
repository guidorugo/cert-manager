import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtensionOID

from ..extensions import db
from ..models.ca import CertificateAuthority
from .crypto_utils import encrypt_private_key, decrypt_private_key


def _generate_key(key_type: str, key_size: int):
    if key_type == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "EC":
        curves = {256: ec.SECP256R1(), 384: ec.SECP384R1(), 521: ec.SECP521R1()}
        return ec.generate_private_key(curves[key_size])
    raise ValueError(f"Unsupported key type: {key_type}")


def _build_subject(attrs: dict) -> x509.Name:
    name_attrs = []
    mapping = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
    }
    for key, oid in mapping.items():
        if attrs.get(key):
            name_attrs.append(x509.NameAttribute(oid, attrs[key]))
    return x509.Name(name_attrs)


def _get_hash_algorithm(key):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return hashes.SHA256()
    return hashes.SHA256()


def create_root_ca(name, subject_attrs, key_type, key_size, validity_days, passphrase,
                   path_length=None, ocsp_url=None):
    key = _generate_key(key_type, key_size)
    subject = _build_subject(subject_attrs)

    now = datetime.now(timezone.utc)
    serial = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(key, _get_hash_algorithm(key))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    enc_key = encrypt_private_key(key, passphrase)

    ca = CertificateAuthority(
        name=name,
        common_name=subject_attrs.get("CN", name),
        serial_number=format(serial, "x"),
        certificate_pem=cert_pem,
        private_key_enc=enc_key,
        parent_id=None,
        is_root=True,
        key_type=key_type,
        key_size=key_size,
        not_before=now,
        not_after=now + timedelta(days=validity_days),
        path_length=path_length,
    )
    db.session.add(ca)
    db.session.commit()
    return ca


def create_intermediate_ca(name, parent_ca, subject_attrs, key_type, key_size,
                           validity_days, passphrase, path_length=None, ocsp_url=None):
    key = _generate_key(key_type, key_size)
    subject = _build_subject(subject_attrs)
    parent_cert = x509.load_pem_x509_certificate(parent_ca.certificate_pem.encode())
    parent_key = decrypt_private_key(parent_ca.private_key_enc, passphrase)

    now = datetime.now(timezone.utc)
    serial = x509.random_serial_number()

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                parent_cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            ),
            critical=False,
        )
    )

    cert = builder.sign(parent_key, _get_hash_algorithm(parent_key))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    enc_key = encrypt_private_key(key, passphrase)

    ca = CertificateAuthority(
        name=name,
        common_name=subject_attrs.get("CN", name),
        serial_number=format(serial, "x"),
        certificate_pem=cert_pem,
        private_key_enc=enc_key,
        parent_id=parent_ca.id,
        is_root=False,
        key_type=key_type,
        key_size=key_size,
        not_before=now,
        not_after=now + timedelta(days=validity_days),
        path_length=path_length,
    )
    db.session.add(ca)
    db.session.commit()
    return ca


def get_ca_chain(ca):
    chain = []
    current = ca
    while current:
        chain.append(current.certificate_pem)
        if current.parent:
            current = current.parent
        else:
            break
    return "\n".join(chain)
