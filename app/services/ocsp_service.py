from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from ..models.certificate import Certificate
from .crypto_utils import decrypt_private_key

OCSP_RESPONSE_VALIDITY_HOURS = 24

_ALLOWED_OCSP_HASHES = (
    hashes.SHA1, hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512,
)


def _request_hash_algorithm(ocsp_req):
    """Mirror the request's CertID hash algorithm in the response.

    Clients match responses to requests by CertID, which includes the hash
    algorithm. openssl defaults to SHA-1, and always answering with SHA-256
    made such clients report "no status found". Falls back to SHA-256 for
    unsupported algorithms.
    """
    try:
        algorithm = ocsp_req.hash_algorithm
        if isinstance(algorithm, _ALLOWED_OCSP_HASHES):
            return algorithm
    except Exception:
        pass
    return hashes.SHA256()

_REVOCATION_REASONS = {
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


def build_ocsp_response(ocsp_request_der: bytes, ca, passphrase: str) -> bytes:
    if not ca.private_key_enc:
        # Certificate-only CA: cannot sign responses. UNAUTHORIZED responses
        # are unsigned, so they can be built without a key.
        response = ocsp.OCSPResponseBuilder().build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED
        )
        return response.public_bytes(serialization.Encoding.DER)

    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    ca_key = decrypt_private_key(ca.private_key_enc, passphrase)

    ocsp_req = ocsp.load_der_ocsp_request(ocsp_request_der)
    serial = ocsp_req.serial_number
    serial_hex = format(serial, "x")
    algorithm = _request_hash_algorithm(ocsp_req)

    certificate = Certificate.query.filter_by(
        serial_number=serial_hex, ca_id=ca.id
    ).first()

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=OCSP_RESPONSE_VALIDITY_HOURS)

    if certificate is None:
        response = ocsp.OCSPResponseBuilder().build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED
        )
        return response.public_bytes(serialization.Encoding.DER)

    cert_obj = x509.load_pem_x509_certificate(certificate.certificate_pem.encode())

    if certificate.is_revoked:
        revocation_time = certificate.revoked_at or now
        reason = _REVOCATION_REASONS.get(
            certificate.revocation_reason, x509.ReasonFlags.unspecified
        )
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=cert_obj,
            issuer=ca_cert,
            algorithm=algorithm,
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            this_update=now,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=reason,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
    else:
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=cert_obj,
            issuer=ca_cert,
            algorithm=algorithm,
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)

    response = builder.sign(ca_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)
