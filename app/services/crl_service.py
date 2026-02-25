from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import CRLEntryExtensionOID

from ..extensions import db
from ..models.certificate import Certificate
from .crypto_utils import decrypt_private_key


REVOCATION_REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}


def revoke_certificate(cert_id, reason="unspecified"):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        raise ValueError("Certificate not found")
    if certificate.is_revoked:
        raise ValueError("Certificate is already revoked")

    certificate.is_revoked = True
    certificate.revoked_at = datetime.now(timezone.utc)
    certificate.revocation_reason = reason
    db.session.commit()
    return certificate


def generate_crl(ca, passphrase, validity_days=7):
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    ca_key = decrypt_private_key(ca.private_key_enc, passphrase)

    now = datetime.now(timezone.utc)
    ca.crl_number += 1

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=validity_days))
        .add_extension(
            x509.CRLNumber(ca.crl_number),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
            ),
            critical=False,
        )
    )

    revoked_certs = Certificate.query.filter_by(ca_id=ca.id, is_revoked=True).all()
    for cert in revoked_certs:
        revoked_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(cert.serial_number, 16))
            .revocation_date(cert.revoked_at or now)
        )

        reason = REVOCATION_REASONS.get(cert.revocation_reason, x509.ReasonFlags.unspecified)
        revoked_builder = revoked_builder.add_extension(
            x509.CRLReason(reason),
            critical=False,
        )

        builder = builder.add_revoked_certificate(revoked_builder.build())

    crl = builder.sign(ca_key, hashes.SHA256())
    db.session.commit()
    return crl


def get_crl_pem(ca, passphrase):
    crl = generate_crl(ca, passphrase)
    return crl.public_bytes(serialization.Encoding.PEM)


def get_crl_der(ca, passphrase):
    crl = generate_crl(ca, passphrase)
    return crl.public_bytes(serialization.Encoding.DER)
