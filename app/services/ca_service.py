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


def detect_parent_ca(cert_pem):
    """Detect if a certificate is self-signed and find its parent CA.

    Returns (is_self_signed, parent_id). Returns (None, None) on parse error.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
    except Exception:
        return (None, None)

    if cert.issuer == cert.subject:
        return (True, None)

    # Search existing CAs for issuer match
    all_cas = CertificateAuthority.query.all()
    for candidate in all_cas:
        try:
            candidate_cert = x509.load_pem_x509_certificate(candidate.certificate_pem.encode())
            if candidate_cert.subject == cert.issuer:
                return (False, candidate.id)
        except Exception:
            continue

    return (False, None)


def import_ca(name, cert_pem, key_pem, passphrase, parent_id=None):
    """Import an existing CA from PEM certificate and private key.

    Validates the certificate is a CA, the key matches, and saves to database.
    """
    MAX_PEM_SIZE = 64 * 1024  # 64KB

    # Size guard
    if len(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem) > MAX_PEM_SIZE:
        raise ValueError("Certificate PEM exceeds 64KB size limit.")
    if len(key_pem.encode() if isinstance(key_pem, str) else key_pem) > MAX_PEM_SIZE:
        raise ValueError("Private key PEM exceeds 64KB size limit.")

    # Parse certificate
    try:
        cert = x509.load_pem_x509_certificate(
            cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        )
    except Exception:
        raise ValueError("Failed to parse certificate PEM. Ensure it is a valid PEM-encoded certificate.")

    # Parse private key
    key_bytes = key_pem.encode() if isinstance(key_pem, str) else key_pem
    try:
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except TypeError:
        raise ValueError("The private key appears to be encrypted. Please provide an unencrypted private key.")
    except Exception:
        raise ValueError("Failed to parse private key PEM. Ensure it is a valid PEM-encoded private key.")

    # Validate key type
    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("Unsupported key type. Only RSA and EC keys are supported.")

    # Key-cert match
    cert_pub_bytes = cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if cert_pub_bytes != key_pub_bytes:
        raise ValueError("The private key does not match the certificate's public key.")

    # BasicConstraints - must be a CA
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            raise ValueError("Certificate has BasicConstraints with ca=False. Only CA certificates can be imported.")
        path_length = bc.value.path_length
    except x509.ExtensionNotFound:
        raise ValueError("Certificate is missing the BasicConstraints extension. Only CA certificates can be imported.")

    # Name uniqueness
    if CertificateAuthority.query.filter_by(name=name).first():
        raise ValueError(f"A CA with the name '{name}' already exists.")

    # Serial uniqueness
    serial_hex = format(cert.serial_number, "x")
    if CertificateAuthority.query.filter_by(serial_number=serial_hex).first():
        raise ValueError(f"A CA with serial number '{serial_hex}' already exists.")

    # Extract metadata
    cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    common_name = cn_attrs[0].value if cn_attrs else name

    if isinstance(private_key, rsa.RSAPrivateKey):
        key_type = "RSA"
        key_size = private_key.key_size
    else:
        key_type = "EC"
        key_size = private_key.key_size

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    # Detect root vs intermediate
    is_self_signed = cert.issuer == cert.subject

    # Resolve parent
    resolved_parent_id = None
    if parent_id is not None and str(parent_id).strip():
        parent_ca = db.session.get(CertificateAuthority, int(parent_id))
        if not parent_ca:
            raise ValueError("Specified parent CA not found.")
        resolved_parent_id = parent_ca.id
    elif not is_self_signed:
        # Auto-detect parent
        _, detected_parent_id = detect_parent_ca(cert_pem)
        resolved_parent_id = detected_parent_id

    # Encrypt and save
    enc_key = encrypt_private_key(key_bytes, passphrase)

    ca = CertificateAuthority(
        name=name,
        common_name=common_name,
        serial_number=serial_hex,
        certificate_pem=cert_pem if isinstance(cert_pem, str) else cert_pem.decode(),
        private_key_enc=enc_key,
        parent_id=resolved_parent_id,
        is_root=is_self_signed and resolved_parent_id is None,
        key_type=key_type,
        key_size=key_size,
        not_before=not_before,
        not_after=not_after,
        path_length=path_length,
    )
    db.session.add(ca)
    db.session.commit()
    return ca
